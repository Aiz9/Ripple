package staticx

import (
	"archive/zip"
	"context"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var reResString = regexp.MustCompile(`resource 0x[0-9a-f]+ string/(\S+)`)

// parseResources extracts string resource values (for secrets and the deep-link
// key) and resolves the network security config from the APK.
func (f *Facts) parseResources(ctx context.Context, apkPath string) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "aapt2", "dump", "resources", apkPath).Output()
	if err != nil {
		f.Warnings = append(f.Warnings, "aapt2 resources: "+err.Error())
		return
	}
	lines := strings.Split(string(out), "\n")
	curName := ""
	for i := 0; i < len(lines); i++ {
		if m := reResString.FindStringSubmatch(lines[i]); m != nil {
			curName = m[1]
			continue
		}
		t := strings.TrimSpace(lines[i])
		if curName == "" || !strings.HasPrefix(t, "() ") {
			continue
		}
		val := strings.Trim(strings.TrimPrefix(t, "() "), `"`)
		f.classifyResource(curName, val, apkPath, ctx)
		curName = ""
	}
}

func (f *Facts) classifyResource(name, val, apkPath string, ctx context.Context) {
	lname := strings.ToLower(name)
	if val == "" || len(val) > 4096 {
		return
	}
	switch {
	case strings.Contains(val, "://") && strings.ContainsAny(val, "@") && credentialURL.MatchString(val):
		f.Secrets = append(f.Secrets, Secret{Kind: "url_credentials", Value: val, Location: "res/values/strings.xml:" + name})
	case lname == "google_api_key" || strings.HasPrefix(val, "AIza"):
		f.Secrets = append(f.Secrets, Secret{Kind: "api_key", Value: val, Location: "res/values/strings.xml:" + name})
	case strings.Contains(lname, "firebase") && strings.Contains(val, "firebaseio.com"):
		f.Secrets = append(f.Secrets, Secret{Kind: "firebase_url", Value: val, Location: "res/values/strings.xml:" + name})
		f.URLs = append(f.URLs, val)
	case (lname == "key" || strings.Contains(lname, "secret") || strings.Contains(lname, "password") || strings.Contains(lname, "token")) && secretLike(lname, val):
		f.Secrets = append(f.Secrets, Secret{Kind: "config_" + lname, Value: val, Location: "res/values/strings.xml:" + name})
	}
	if strings.HasPrefix(val, "http") {
		f.URLs = append(f.URLs, val)
	}
}

var credentialURL = regexp.MustCompile(`://[^/@\s]+:[^/@\s]+@`)

// secretLike filters out UI strings (content descriptions, vector-drawable path
// data, hints, labels) that merely contain "password"/"key" in the resource name.
func secretLike(name, val string) bool {
	for _, skip := range []string{"description", "path_", "eye", "hint", "label", "title", "toggle", "visible", "strike"} {
		if strings.Contains(name, skip) {
			return false
		}
	}
	if strings.ContainsAny(val, " ") || len(val) < 6 || len(val) > 256 {
		return false
	}
	// Vector path data begins with a move command and coordinates.
	if (val[0] == 'M' || val[0] == 'm') && strings.ContainsAny(val, ",") {
		return false
	}
	return true
}

// parseNativeLibs lists bundled .so names from the APK.
func (f *Facts) parseNativeLibs(ctx context.Context, apkPath string) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return
	}
	defer zr.Close()
	seen := map[string]bool{}
	for _, file := range zr.File {
		if strings.HasPrefix(file.Name, "lib/") && strings.HasSuffix(file.Name, ".so") {
			base := file.Name[strings.LastIndexByte(file.Name, '/')+1:]
			if !seen[base] {
				seen[base] = true
				f.NativeLibs = append(f.NativeLibs, base)
				// Mine endpoints/secrets from the app's own native code (Flutter's
				// libapp.so above all) — scan one arch per library, they share strings.
				if base == "libapp.so" || base == "libflutter.so" || strings.HasPrefix(base, "libapp") {
					f.scanNativeStrings(file, file.Name)
				}
			}
		}
		if file.Name == "res/xml/network_security_config.xml" && f.NetworkConfig != "" {
			f.resolveNetworkConfig(file)
		}
	}
}

func (f *Facts) resolveNetworkConfig(file *zip.File) {
	rc, err := file.Open()
	if err != nil {
		return
	}
	defer rc.Close()
	buf := make([]byte, 8192)
	n, _ := rc.Read(buf)
	// Binary XML: extract readable strings and cleartext flag heuristically.
	text := string(buf[:n])
	if strings.Contains(strings.ToLower(text), "cleartexttrafficpermitted") {
		b := true
		f.UsesCleartext = &b
	}
}

var _ = time.Second
