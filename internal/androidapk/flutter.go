package androidapk

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
)

// FlutterReport contains deep inspection results for Flutter-based APKs.
type FlutterReport struct {
	IsFlutter        bool      `json:"is_flutter"`
	BuildType        string    `json:"build_type"` // "AOT (Release/Profile)", "JIT (Debug)", or "Unknown"
	EngineLibraries  []string  `json:"engine_libraries"`
	AppLibraries     []string  `json:"app_libraries"`
	Architectures    []string  `json:"architectures"`
	EngineCommit     string    `json:"engine_commit,omitempty"`
	DartVersion      string    `json:"dart_version,omitempty"`
	BundledAssets    []string  `json:"bundled_assets"`
	BundledCerts     []string  `json:"bundled_certs"`
	DiscoveredURLs   []string  `json:"discovered_urls"`
	PlatformChannels []string  `json:"platform_channels"`
	HardcodedSecrets []string  `json:"hardcoded_secrets"`
	SecurityFindings []Finding `json:"security_findings"`
	Limitations      []string  `json:"limitations"`
}

var (
	urlRegex     = regexp.MustCompile(`https?://[a-zA-Z0-9][-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_+.~#?&/=]*`)
	channelRegex = regexp.MustCompile(`\b([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+(?:/channel|/methods|/events)?)\b`)
	secretRegex  = regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password|auth|bearer)\s*[:=]\s*["']?([A-Za-z0-9._~+/=-]{8,128})["']?`)
	commitRegex  = regexp.MustCompile(`[0-9a-f]{40}`)
)

// InspectFlutter inspects an open APK ZIP reader for Flutter-specific artifacts.
func InspectFlutter(z *zip.Reader) (*FlutterReport, error) {
	rep := &FlutterReport{
		EngineLibraries:  []string{},
		AppLibraries:     []string{},
		Architectures:    []string{},
		BundledAssets:    []string{},
		BundledCerts:     []string{},
		DiscoveredURLs:   []string{},
		PlatformChannels: []string{},
		HardcodedSecrets: []string{},
		SecurityFindings: []Finding{},
		Limitations:      []string{},
	}

	archMap := make(map[string]bool)
	var appLibFile *zip.File
	var flutterLibFile *zip.File
	hasKernelBlob := false

	for _, entry := range z.File {
		name := entry.Name

		// Check for Flutter engine & app binaries
		if strings.HasPrefix(name, "lib/") {
			parts := strings.Split(name, "/")
			if len(parts) >= 3 {
				arch := parts[1]
				filename := parts[2]
				if filename == "libflutter.so" {
					rep.EngineLibraries = append(rep.EngineLibraries, name)
					archMap[arch] = true
					if flutterLibFile == nil || arch == "arm64-v8a" {
						flutterLibFile = entry
					}
				} else if filename == "libapp.so" {
					rep.AppLibraries = append(rep.AppLibraries, name)
					archMap[arch] = true
					if appLibFile == nil || arch == "arm64-v8a" {
						appLibFile = entry
					}
				}
			}
		}

		// Check for Flutter assets directory
		if strings.HasPrefix(name, "assets/flutter_assets/") {
			rel := strings.TrimPrefix(name, "assets/flutter_assets/")
			if rel != "" && !strings.HasSuffix(rel, "/") {
				rep.BundledAssets = append(rep.BundledAssets, rel)
				if rel == "kernel_blob.bin" {
					hasKernelBlob = true
				}
				// Check for bundled SSL/TLS certificates
				ext := strings.ToLower(path.Ext(rel))
				if ext == ".cer" || ext == ".crt" || ext == ".pem" || ext == ".der" || ext == ".p12" || ext == ".pfx" {
					rep.BundledCerts = append(rep.BundledCerts, rel)
				}
			}
		}
	}

	if len(rep.EngineLibraries) == 0 && len(rep.AppLibraries) == 0 && len(rep.BundledAssets) == 0 {
		rep.IsFlutter = false
		return rep, nil
	}

	rep.IsFlutter = true
	for arch := range archMap {
		rep.Architectures = append(rep.Architectures, arch)
	}
	sort.Strings(rep.Architectures)
	sort.Strings(rep.BundledAssets)
	sort.Strings(rep.BundledCerts)

	// Determine build type
	if hasKernelBlob {
		rep.BuildType = "JIT (Debug)"
		rep.SecurityFindings = append(rep.SecurityFindings, Finding{
			ID:             "FLUTTER_DEBUG_BUILD_ARTIFACTS",
			Title:          "Flutter Debug Kernel Blob Present in Package",
			Severity:       "high",
			Evidence:       "Found assets/flutter_assets/kernel_blob.bin. JIT bytecode exposes complete Dart sources and symbols.",
			Recommendation: "Compile release builds with `flutter build apk --release` to enable AOT snapshot compilation.",
			Status:         "candidate",
		})
	} else if len(rep.AppLibraries) > 0 {
		rep.BuildType = "AOT (Release/Profile)"
	} else {
		rep.BuildType = "Unknown (Hybrid or Engine-only)"
	}

	// Flag bundled certificates in flutter_assets (potential pinning or private key exposure)
	if len(rep.BundledCerts) > 0 {
		rep.SecurityFindings = append(rep.SecurityFindings, Finding{
			ID:             "FLUTTER_BUNDLED_CERTIFICATES",
			Title:          "Certificates Bundled in Flutter Assets",
			Severity:       "medium",
			Evidence:       fmt.Sprintf("Bundled certificate files: %s", strings.Join(rep.BundledCerts, ", ")),
			Recommendation: "Verify that bundled certificates do not contain private keys. If used for SSL pinning, implement resilient pinning verification.",
			Status:         "candidate",
		})
	}

	// Inspect libflutter.so if available (extract engine commit hash)
	if flutterLibFile != nil {
		if rc, err := flutterLibFile.Open(); err == nil {
			buf := make([]byte, 1024*1024) // Read up to 1MB sample
			n, _ := io.ReadFull(rc, buf)
			rc.Close()
			if n > 0 {
				match := commitRegex.Find(buf[:n])
				if len(match) > 0 {
					rep.EngineCommit = string(match)
				}
			}
		}
	}

	// Inspect libapp.so (extract ASCII strings, URLs, potential API keys, channel candidates)
	if appLibFile != nil {
		extractLibAppStrings(appLibFile, rep)
	} else {
		rep.Limitations = append(rep.Limitations, "libapp.so was not found; Dart AOT string extraction skipped")
	}

	rep.Limitations = append(rep.Limitations,
		"Flutter uses embedded BoringSSL inside libflutter.so; Android OS TrustManager and Java OkHttp hooks do not capture its traffic.",
		"Dart AOT machine code requires specialized symbol recovery (e.g. Blutter) for full functional disassembly.",
	)

	return rep, nil
}

// extractLibAppStrings extracts string tokens, URLs, and potential secrets from libapp.so.
func extractLibAppStrings(file *zip.File, rep *FlutterReport) {
	rc, err := file.Open()
	if err != nil {
		rep.Limitations = append(rep.Limitations, fmt.Sprintf("Failed to open %s: %v", file.Name, err))
		return
	}
	defer rc.Close()

	// Read full or capped libapp.so content (up to 32MB)
	limit := int64(32 * 1024 * 1024)
	if file.UncompressedSize64 > 0 && int64(file.UncompressedSize64) < limit {
		limit = int64(file.UncompressedSize64)
	}

	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil && err != io.EOF {
		rep.Limitations = append(rep.Limitations, fmt.Sprintf("Error reading %s: %v", file.Name, err))
		return
	}

	// Check ELF header
	if len(data) > 4 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		if reader, err := elf.NewFile(bytes.NewReader(data)); err == nil {
			_ = reader // ELF is valid
		}
	}

	// Extract printable ASCII strings of length >= 6
	urlSet := make(map[string]bool)
	channelSet := make(map[string]bool)
	secretSet := make(map[string]bool)

	// Scan contiguous ASCII bytes
	var strBuf []byte
	scanString := func(s string) {
		for _, u := range urlRegex.FindAllString(s, -1) {
			if !strings.Contains(u, "schemas.android.com") && !strings.Contains(u, "w3.org") {
				urlSet[u] = true
			}
		}
		if strings.Contains(s, "flutter/") || strings.Contains(s, "plugins.flutter.io") || strings.HasSuffix(s, "/methods") {
			channelSet[s] = true
		}
		if secretRegex.MatchString(s) {
			secretSet[s] = true
		}
	}

	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\t' {
			strBuf = append(strBuf, b)
			if len(strBuf) > 512 {
				scanString(string(strBuf))
				strBuf = strBuf[:0]
			}
		} else {
			if len(strBuf) >= 6 {
				scanString(string(strBuf))
			}
			strBuf = strBuf[:0]
		}
	}
	if len(strBuf) >= 6 {
		scanString(string(strBuf))
	}

	for u := range urlSet {
		rep.DiscoveredURLs = append(rep.DiscoveredURLs, u)
	}
	sort.Strings(rep.DiscoveredURLs)

	for c := range channelSet {
		rep.PlatformChannels = append(rep.PlatformChannels, c)
	}
	sort.Strings(rep.PlatformChannels)

	for s := range secretSet {
		rep.HardcodedSecrets = append(rep.HardcodedSecrets, s)
	}
	sort.Strings(rep.HardcodedSecrets)

	if len(rep.HardcodedSecrets) > 0 {
		rep.SecurityFindings = append(rep.SecurityFindings, Finding{
			ID:             "FLUTTER_HARDCODED_SECRETS_IN_AOT",
			Title:          "Potential Hardcoded Secrets Recovered from Dart AOT Binary",
			Severity:       "medium",
			Evidence:       fmt.Sprintf("Discovered %d potential secret tokens in libapp.so strings pool", len(rep.HardcodedSecrets)),
			Recommendation: "Avoid embedding production API secrets, keys, or passwords in client-side Dart source code.",
			Status:         "candidate",
		})
	}
}

// SHA256 returns the hexadecimal SHA-256 hash of byte slice.
func hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
