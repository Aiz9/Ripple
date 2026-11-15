// Package staticx decompiles an APK (jadx for code, aapt2 for the manifest and
// resources) and extracts the static facts that drive dynamic device tests:
// exported components, intent extras, provider authorities, deep-link params,
// WebView/JS interfaces, crypto call sites, SharedPreferences names and secrets.
// Results are cached by APK SHA-256.
package staticx

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Component is one declared application component.
type Component struct {
	Kind       string   `json:"kind"` // activity | receiver | service | provider
	Name       string   `json:"name"`
	Exported   bool     `json:"exported"`
	Permission string   `json:"permission,omitempty"`
	Authority  string   `json:"authority,omitempty"`
	Actions    []string `json:"actions,omitempty"`
	ExtraKeys  []string `json:"extra_keys,omitempty"`
}

// DeepLink is one intent-filter data entry on an exported activity.
type DeepLink struct {
	Activity  string   `json:"activity"`
	Scheme    string   `json:"scheme"`
	Host      string   `json:"host,omitempty"`
	Path      string   `json:"path,omitempty"`
	QueryKeys []string `json:"query_keys,omitempty"`
}

// CallSite is one security-relevant code location.
type CallSite struct {
	Kind     string `json:"kind"` // cipher_ecb | hardcoded_key | md5 | insecure_random | ...
	Detail   string `json:"detail"`
	Location string `json:"location"` // file:line
}

// Secret is a recovered credential/key-shaped literal.
type Secret struct {
	Kind     string `json:"kind"`
	Value    string `json:"value"`
	Location string `json:"location"`
}

// Facts is the static profile used by dynamic workers.
type Facts struct {
	CacheVersion     int               `json:"cache_version,omitempty"`
	ToolVersions     map[string]string `json:"tool_versions,omitempty"`
	Complete         bool              `json:"complete"`
	Package          string            `json:"package"`
	SHA256           string            `json:"sha256"`
	MinSDK           int               `json:"min_sdk"`
	TargetSDK        int               `json:"target_sdk"`
	Debuggable       bool              `json:"debuggable"`
	AllowBackup      bool              `json:"allow_backup"`
	UsesCleartext    *bool             `json:"uses_cleartext,omitempty"`
	NetworkConfig    string            `json:"network_security_config,omitempty"`
	Components       []Component       `json:"components"`
	DeepLinks        []DeepLink        `json:"deep_links"`
	NativeMethods    []string          `json:"native_methods,omitempty"`
	NativeLibs       []string          `json:"native_libs,omitempty"`
	JSInterfaces     []string          `json:"js_interfaces,omitempty"`
	WebViewFlags     []string          `json:"webview_flags,omitempty"`
	ProviderPaths    []string          `json:"provider_paths,omitempty"`
	PrefsNames       []string          `json:"prefs_names,omitempty"`
	CryptoCallSites  []CallSite        `json:"crypto_call_sites,omitempty"`
	Secrets          []Secret          `json:"secrets,omitempty"`
	DynamicCodeLoads []CallSite        `json:"dynamic_code_loads,omitempty"`
	URLs             []string          `json:"urls,omitempty"`
	Warnings         []string          `json:"warnings,omitempty"`
	SourceRoot       string            `json:"source_root,omitempty"`
	GeneratedAt      time.Time         `json:"generated_at"`
}

// ToolCheck reports availability of the decompilers.
func ToolCheck() map[string]bool {
	out := map[string]bool{}
	for _, t := range []string{"jadx", "aapt2", "apktool"} {
		_, err := exec.LookPath(t)
		out[t] = err == nil
	}
	return out
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if n, err := io.Copy(h, io.LimitReader(f, (512<<20)+1)); err != nil {
		return "", err
	} else if n > 512<<20 {
		return "", fmt.Errorf("APK exceeds the 512 MiB analysis limit")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

const cacheVersion = 2

// Analyze reuses only complete, version-matched facts. Every extraction uses a
// new source directory and publishes facts atomically; a killed decompiler or
// concurrent process cannot turn a partial source tree into a reusable result.
func Analyze(ctx context.Context, apkPath, cacheDir string) (*Facts, error) {
	sha, err := fileSHA256(apkPath)
	if err != nil {
		return nil, err
	}
	base, err := filepath.Abs(filepath.Join(cacheDir, sha))
	if err != nil {
		return nil, err
	}
	versions := toolVersions(ctx)
	factsPath := filepath.Join(base, "facts.json")
	if f := cachedFacts(factsPath, sha, versions); f != nil {
		return f, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, err
	}
	f := &Facts{SHA256: sha, GeneratedAt: time.Now().UTC(), CacheVersion: cacheVersion, ToolVersions: versions}
	srcRoot, err := os.MkdirTemp(base, "analysis-")
	if err != nil {
		return nil, err
	}
	// Keep partial facts available for this run but never cache them as complete.
	if versions["jadx"] != "unavailable" {
		jctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
		_, err := exec.CommandContext(jctx, "jadx", "-q", "--no-res", "-d", srcRoot, apkPath).CombinedOutput()
		cancel()
		if err != nil {
			// Tool output can include APK-controlled literals. Keep it out of
			// report warnings and provider context.
			f.Warnings = append(f.Warnings, "jadx decompilation incomplete; code-derived facts are partial")
		}
	} else {
		f.Warnings = append(f.Warnings, "jadx not installed; code-derived facts unavailable")
	}
	f.SourceRoot = srcRoot
	if err := f.parseManifest(ctx, apkPath); err != nil {
		f.Warnings = append(f.Warnings, "manifest parse: "+err.Error())
	}
	f.parseResources(ctx, apkPath)
	f.parseNativeLibs(ctx, apkPath)
	f.scanSources(filepath.Join(srcRoot, "sources"))
	if info, err := os.Stat(filepath.Join(srcRoot, "sources", filepath.FromSlash(strings.ReplaceAll(f.Package, ".", "/")))); err != nil || !info.IsDir() || f.Package == "" {
		f.Warnings = append(f.Warnings, "Application source tree unavailable; code-derived coverage is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return f, err
	}
	f.Complete = len(f.Warnings) == 0
	sort.Slice(f.Components, func(i, j int) bool { return f.Components[i].Name < f.Components[j].Name })
	if f.Complete {
		if err := publishFacts(factsPath, f); err != nil {
			f.Warnings = append(f.Warnings, "Static cache could not be persisted; facts are available for this run only")
		}
	}
	return f, nil
}

func toolVersions(ctx context.Context) map[string]string {
	versions := map[string]string{}
	for _, spec := range []struct{ name, flag string }{{"jadx", "--version"}, {"aapt2", "version"}} {
		toolCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		out, err := exec.CommandContext(toolCtx, spec.name, spec.flag).Output()
		cancel()
		if err != nil || len(out) == 0 || len(out) > 4096 {
			versions[spec.name] = "unavailable"
		} else {
			versions[spec.name] = strings.TrimSpace(string(out))
		}
	}
	return versions
}

func cachedFacts(path, sha string, versions map[string]string) *Facts {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var f Facts
	if json.Unmarshal(raw, &f) != nil || !f.Complete || f.CacheVersion != cacheVersion || f.SHA256 != sha || f.Package == "" {
		return nil
	}
	for _, tool := range []string{"jadx", "aapt2"} {
		if versions[tool] == "" || versions[tool] == "unavailable" || f.ToolVersions[tool] != versions[tool] {
			return nil
		}
	}
	appSources := filepath.Join(f.SourceRoot, "sources", filepath.FromSlash(strings.ReplaceAll(f.Package, ".", "/")))
	if info, err := os.Stat(appSources); err != nil || !info.IsDir() {
		return nil
	}
	return &f
}

func publishFacts(path string, facts *Facts) error {
	raw, err := json.MarshalIndent(facts, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".facts-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func lastErr(s string) string {
	s = strings.TrimSpace(s)
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(strings.ToLower(lines[i]), "error") {
			return clip(lines[i], 200)
		}
	}
	return clip(s, 200)
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ExportedActivities returns names of exported activities.
func (f *Facts) ExportedActivities() []Component { return f.byKind("activity", true) }

func (f *Facts) byKind(kind string, exportedOnly bool) []Component {
	out := []Component{}
	for _, c := range f.Components {
		if c.Kind == kind && (!exportedOnly || c.Exported) {
			out = append(out, c)
		}
	}
	return out
}

// Component returns a declared component by (unqualified or full) name.
func (f *Facts) Component(name string) *Component {
	for i := range f.Components {
		if f.Components[i].Name == name || strings.HasSuffix(f.Components[i].Name, "."+name) {
			return &f.Components[i]
		}
	}
	return nil
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// readSources walks decompiled .java files, calling fn with each file's path and
// content. It bounds total bytes read.
func readSources(root string, fn func(path, content string)) {
	total := int64(0)
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".java") || total > 256<<20 {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		total += int64(len(b))
		fn(path, string(b))
		return nil
	})
}

var _ = bufio.NewScanner
