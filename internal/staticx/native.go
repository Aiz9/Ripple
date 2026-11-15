package staticx

import (
	"archive/zip"
	"io"
	"regexp"
	"strings"
)

// Native libraries — above all Flutter's libapp.so (the AOT-compiled Dart code) —
// carry the endpoints and secrets that never appear in the Java/dex or resources.
// A Flutter banking app's real API host lives here, so without mining the .so the
// static layer is blind to the app's actual backend. scanNativeStrings extracts
// printable strings from a bundled library and recovers URLs and secret literals.

var (
	reNativeURL    = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}`)
	reGoogleAPIKey = regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)
	reJWT          = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`)
	reFirebaseDB   = regexp.MustCompile(`https?://[a-z0-9-]+\.firebaseio\.com`)
)

const (
	maxNativeScanBytes = 80 << 20 // cap per library
	minNativeStringLen = 6
	maxNativeFindings  = 400 // per library, to bound noise
)

// scanNativeStrings reads one .so from the APK, extracts printable strings, and
// appends recovered URLs/secrets to the facts, tagged with the library path so the
// evidence is traceable (e.g. lib/arm64-v8a/libapp.so).
func (f *Facts) scanNativeStrings(file *zip.File, libPath string) {
	rc, err := file.Open()
	if err != nil {
		return
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxNativeScanBytes))
	if err != nil || len(data) == 0 {
		return
	}
	loc := libPath + " (native)"
	seenURL := map[string]bool{}
	seenSecret := map[string]bool{}
	found := 0
	for _, s := range extractPrintable(data, minNativeStringLen) {
		if found >= maxNativeFindings {
			break
		}
		for _, u := range reNativeURL.FindAllString(s, -1) {
			u = strings.TrimRight(u, ".,;)}\"'")
			if seenURL[u] || len(u) > 300 {
				continue
			}
			seenURL[u] = true
			found++
			f.URLs = append(f.URLs, u)
			if reFirebaseDB.MatchString(u) {
				f.Secrets = append(f.Secrets, Secret{Kind: "firebase_url", Value: u, Location: loc})
			}
		}
		for _, k := range reGoogleAPIKey.FindAllString(s, -1) {
			if !seenSecret[k] {
				seenSecret[k] = true
				found++
				f.Secrets = append(f.Secrets, Secret{Kind: "api_key", Value: k, Location: loc})
			}
		}
		for _, j := range reJWT.FindAllString(s, -1) {
			if !seenSecret[j] {
				seenSecret[j] = true
				found++
				f.Secrets = append(f.Secrets, Secret{Kind: "jwt", Value: j, Location: loc})
			}
		}
	}
	f.URLs = dedupe(f.URLs)
	f.Secrets = dedupeSecrets(f.Secrets)
}

// extractPrintable returns runs of printable ASCII of at least minLen bytes.
func extractPrintable(data []byte, minLen int) []string {
	var out []string
	start := -1
	for i, b := range data {
		if b >= 0x20 && b <= 0x7e {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if i-start >= minLen {
				out = append(out, string(data[start:i]))
			}
			start = -1
		}
	}
	if start >= 0 && len(data)-start >= minLen {
		out = append(out, string(data[start:]))
	}
	return out
}
