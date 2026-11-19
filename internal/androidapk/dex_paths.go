package androidapk

import (
	"bytes"
	"regexp"
	"strings"
)

// Host-less API path extraction. The literal-URL scan only captures hardcoded
// base URLs, which apps frequently switch at runtime (BuildConfig flavor, remote
// config, environment toggle). The endpoint PATHS, however, are declared in code
// (Retrofit/OkHttp annotations, path constants) as host-less templates like
// "/v1/accounts/{id}". Extracting those lets the agent combine them with the base
// URL actually observed in runtime proxy traffic, surfacing endpoints that only
// appear once the app runs. These are string-literal observations, not executed
// code; obfuscated or concatenated paths still need runtime evidence.

// apiPathRe matches a 2+ segment path, allowing {param} and :param templates.
var apiPathRe = regexp.MustCompile(`/(?:[A-Za-z0-9._~%-]+|\{[A-Za-z0-9_]+\}|:[A-Za-z0-9_]+)(?:/(?:[A-Za-z0-9._~%-]+|\{[A-Za-z0-9_]+\}|:[A-Za-z0-9_]+))+/?`)

var versionSegRe2 = regexp.MustCompile(`(?i)/v[0-9]+(?:/|$)`)

// httpClientMarkers gate path extraction: a DEX that references an HTTP client is
// one whose path-looking strings are very likely API routes, which keeps file-system
// and resource paths out of the results.
var httpClientMarkers = [][]byte{
	[]byte("retrofit2"), []byte("okhttp3"), []byte("Lokhttp"), []byte("HttpUrl"),
	[]byte("HttpURLConnection"), []byte("com/android/volley"), []byte("io/ktor"),
	[]byte("cronet"), []byte("apache/http"),
}

func usesHTTPClient(data []byte) bool {
	for _, m := range httpClientMarkers {
		if bytes.Contains(data, m) {
			return true
		}
	}
	return false
}

// nonAPIRoots are first-segment prefixes that mark a filesystem/resource path.
var nonAPIRoots = []string{
	"/data/", "/system/", "/storage/", "/sdcard/", "/dev/", "/proc/", "/sys/",
	"/res/", "/assets/", "/meta-inf/", "/android_asset", "/android_res", "/mnt/",
	"/vendor/", "/product/", "/etc/", "/apk/", "/cache/", "/tmp/", "/bin/", "/usr/",
	"/lib/", "/fonts/", "/drawable", "/mipmap", "/layout/", "/values/",
}

var staticAssetExt = []string{
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".so", ".dex", ".ttf",
	".otf", ".css", ".js", ".html", ".xml", ".properties", ".kt", ".java", ".class", ".md",
}

// apiKeywords mark a host-less path as an API route even without a version/param.
var apiKeywords = []string{
	"api", "rest", "graphql", "oauth", "auth", "token", "user", "account", "payment",
	"transfer", "transaction", "order", "login", "logout", "register", "profile",
	"wallet", "balance", "card", "beneficiar", "otp", "verify", "session", "notif",
	"device", "kyc", "statement", "limit", "upi", "qr",
}

// apiPathLikely filters a candidate path to keep only plausible API routes.
func apiPathLikely(p string) bool {
	lower := strings.ToLower(p)
	for _, bad := range nonAPIRoots {
		if strings.HasPrefix(lower, bad) {
			return false
		}
	}
	for _, ext := range staticAssetExt {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	if versionSegRe2.MatchString(p) || strings.ContainsAny(p, "{}") || strings.Contains(p, "/:") {
		return true
	}
	for _, kw := range apiKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// dexAPIPaths extracts host-less API path templates from an entry's bytes, gated
// on the entry using an HTTP client. shortcut: the gate is per-entry; a path in a
// dex that itself never names an HTTP client is missed — upgrade to a cross-dex
// gate if such apps appear.
func dexAPIPaths(data []byte) []string {
	if !usesHTTPClient(data) {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range apiPathRe.FindAll(data, 8000) {
		p := strings.TrimRight(string(m), "/")
		if p == "" || strings.Count(p, "/") < 2 || !apiPathLikely(p) {
			continue
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
		if len(out) >= 500 {
			break
		}
	}
	return out
}
