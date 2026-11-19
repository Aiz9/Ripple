package androidapk

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Aiz9/ripple/internal/mobiletest"
)

type Component struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Exported   string `json:"exported"`
	Permission string `json:"permission"`
}

type Finding struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation"`
	Status         string `json:"status"`
}

type Report struct {
	NetworkConfig   []ConfigurationObservation `json:"network_configuration"`
	Certificates    []CertificateMetadata      `json:"certificates"`
	Profile         mobiletest.Profile         `json:"profile"`
	Flutter         *FlutterReport             `json:"flutter,omitempty"`
	Package         string                     `json:"package"`
	VersionName     string                     `json:"version_name"`
	VersionCode     string                     `json:"version_code"`
	MinSDK          string                     `json:"min_sdk"`
	TargetSDK       string                     `json:"target_sdk"`
	SHA256          string                     `json:"sha256"`
	Size            int64                      `json:"size"`
	Files           int                        `json:"files"`
	DexFiles        int                        `json:"dex_files"`
	NativeLibraries []string                   `json:"native_libraries"`
	Permissions     []string                   `json:"permissions"`
	Components      []Component                `json:"components"`
	Findings        []Finding                  `json:"findings"`
	Warnings        []string                   `json:"warnings"`
}

func Analyze(path string) (*Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := preflightAPK(f, fi.Size()); err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return nil, err
	}
	z, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return nil, fmt.Errorf("invalid APK ZIP archive: %w", err)
	}
	if len(z.File) > 100000 {
		return nil, fmt.Errorf("APK contains too many entries")
	}
	r := &Report{SHA256: hex.EncodeToString(h.Sum(nil)), Size: fi.Size(), Files: len(z.File), Permissions: []string{}, Components: []Component{}, Findings: []Finding{}, NativeLibraries: []string{}, Warnings: []string{}}
	var manifest *zip.File
	for _, entry := range z.File {
		if entry.Name == "AndroidManifest.xml" {
			if manifest != nil {
				return nil, fmt.Errorf("duplicate APK manifest")
			}
			manifest = entry
		}
		if strings.HasPrefix(entry.Name, "classes") && strings.HasSuffix(entry.Name, ".dex") && !strings.Contains(entry.Name, "/") {
			r.DexFiles++
		}
		if strings.HasPrefix(entry.Name, "lib/") && strings.HasSuffix(entry.Name, ".so") {
			r.NativeLibraries = append(r.NativeLibraries, entry.Name)
		}
	}
	if manifest == nil {
		return nil, fmt.Errorf("not an APK: AndroidManifest.xml is missing")
	}
	if manifest.UncompressedSize64 > 4<<20 {
		return nil, fmt.Errorf("manifest exceeds 4 MiB")
	}
	m, err := manifest.Open()
	if err != nil {
		return nil, err
	}
	defer m.Close()
	data, err := io.ReadAll(io.LimitReader(m, (4<<20)+1))
	if err != nil {
		return nil, err
	}
	root, err := parseManifest(data)
	if err != nil {
		return nil, err
	}
	r.Package = root.attrs["package"]
	if r.Package == "" {
		return nil, fmt.Errorf("manifest package is missing")
	}
	r.VersionName = root.attr("versionName")
	r.VersionCode = root.attr("versionCode")
	r.MinSDK = "1"
	var app *element
	for _, e := range root.children {
		switch e.name {
		case "uses-sdk":
			if v := e.attr("minSdkVersion"); v != "" {
				r.MinSDK = v
			}
			r.TargetSDK = e.attr("targetSdkVersion")
		case "uses-permission", "uses-permission-sdk-23":
			if p := e.attr("name"); p != "" {
				r.Permissions = append(r.Permissions, p)
			}
		case "application":
			app = e
		}
	}
	if app == nil {
		return nil, fmt.Errorf("manifest application is missing")
	}
	if r.TargetSDK == "" {
		r.TargetSDK = r.MinSDK
	}
	add := func(id, title, severity, evidence, fix, status string) {
		r.Findings = append(r.Findings, Finding{id, title, severity, evidence, fix, status})
	}
	if app.attr("debuggable") == "true" {
		add("debuggable", "Debugging enabled", "high", "AndroidManifest.xml: application android:debuggable=true", "Disable debugging in release builds; verify the installed build is not debuggable.", "observed")
	}
	if app.attr("testOnly") == "true" {
		add("test-only", "Test-only application", "info", "AndroidManifest.xml: application android:testOnly=true", "Verify this is the intended testing artifact, rather than a production release.", "observed")
	}
	if app.attr("allowBackup") != "false" {
		v := app.attr("allowBackup")
		if v == "" {
			v = "omitted (platform default true)"
		}
		add("backup", "Review backup policy", "low", "AndroidManifest.xml: application android:allowBackup="+v+"; fullBackupContent="+app.attr("fullBackupContent")+"; dataExtractionRules="+app.attr("dataExtractionRules"), "Review backup inclusion/exclusion rules on the supported Android versions. This flag alone does not prove sensitive data exposure.", "review")
	}
	target, targetErr := strconv.Atoi(r.TargetSDK)
	if app.attr("usesCleartextTraffic") == "true" {
		add("cleartext", "Cleartext traffic allowed by manifest", "medium", "AndroidManifest.xml: application android:usesCleartextTraffic=true; networkSecurityConfig="+app.attr("networkSecurityConfig"), "Inspect network security configuration and actual requests. Enforce TLS for sensitive traffic.", "review")
	} else if app.attr("usesCleartextTraffic") == "" && targetErr == nil && target < 28 {
		add("cleartext-default", "Review legacy cleartext default", "medium", "AndroidManifest.xml: usesCleartextTraffic omitted; targetSdkVersion="+r.TargetSDK+"; networkSecurityConfig="+app.attr("networkSecurityConfig"), "Inspect network security configuration and runtime traffic before confirming any exposure.", "review")
	}
	for _, e := range app.children {
		switch e.name {
		case "activity", "activity-alias", "service", "receiver", "provider":
		default:
			continue
		}
		name := e.attr("name")
		if strings.HasPrefix(name, ".") {
			name = r.Package + name
		} else if name != "" && !strings.Contains(name, ".") {
			name = r.Package + "." + name
		}
		exported := e.attr("exported")
		if exported == "" {
			exported = "false (default)"
			if e.name == "provider" {
				if targetErr != nil {
					exported = "unknown"
				} else if target < 17 {
					exported = "true (legacy default)"
				}
			} else {
				for _, child := range e.children {
					if child.name == "intent-filter" {
						exported = "true (legacy intent-filter default)"
						if targetErr != nil || target >= 31 {
							exported = "missing (explicit value required for target 31+)"
						}
						break
					}
				}
			}
		}
		permission := e.attr("permission")
		if permission == "" {
			permission = app.attr("permission")
		}
		r.Components = append(r.Components, Component{e.name, name, exported, permission})
		if strings.HasPrefix(exported, "true") {
			add(fmt.Sprintf("exported-%d", len(r.Components)), "Review exported "+e.name+": "+name, "info", "AndroidManifest.xml: "+e.name+" "+name+"; exported="+exported+"; permission="+permission, "Confirm intended exposure and validate authorization, input handling, and provider read/write permissions. Exported components alone are not vulnerabilities.", "review")
		}
	}
	for _, attr := range []string{"debuggable", "allowBackup", "usesCleartextTraffic"} {
		if strings.HasPrefix(app.attr(attr), "@") {
			r.Warnings = append(r.Warnings, "Unresolved resource reference for application "+attr+"; inspect resources before drawing conclusions.")
		}
	}
	r.NetworkConfig = inspectNetworkConfiguration(z, app, r)
	inspectCertificates(f, fi.Size(), z, r)
	r.Profile = inspectProfile(z, app, r)
	if fl, err := InspectFlutter(z); err == nil && fl.IsFlutter {
		r.Flutter = fl
		r.Findings = append(r.Findings, fl.SecurityFindings...)
	}
	r.Warnings = append(r.Warnings, "Offline manifest and bounded technology/indicator inspection only. Code behavior, resource values, signing validity and runtime security have not been verified.")
	sort.Strings(r.Permissions)
	sort.Strings(r.NativeLibraries)
	return r, nil
}
