package staticx

import (
	"path/filepath"
	"regexp"
	"strings"
)

var (
	reCipher      = regexp.MustCompile(`Cipher\.getInstance\(\s*"([^"]+)"`)
	reSecretKey   = regexp.MustCompile(`new SecretKeySpec\(`)
	reKeyLiteral  = regexp.MustCompile(`(?:String\s+\w*(?:KEY|key|Key)\w*\s*=\s*|KEY\s*=\s*)"([^"]{4,})"`)
	reMD5         = regexp.MustCompile(`MessageDigest\.getInstance\(\s*"(MD5|SHA-1|SHA1)"`)
	reRandom      = regexp.MustCompile(`new java\.util\.Random\(|new Random\(`)
	reGetExtra    = regexp.MustCompile(`get(?:String|Int|Boolean|Parcelable|Serializable|Long|Float|Double|Bundle|CharSequence)?Extra\(\s*"([^"]+)"`)
	rePutExtra    = regexp.MustCompile(`putExtra\(\s*"([^"]+)"`)
	reAddURI      = regexp.MustCompile(`addURI\(\s*"([^"]+)"\s*,\s*"([^"]+)"`)
	reJSInterface = regexp.MustCompile(`addJavascriptInterface\(\s*[^,]+,\s*"([^"]+)"`)
	reWebSetting  = regexp.MustCompile(`set(JavaScriptEnabled|AllowFileAccess|AllowUniversalAccessFromFileURLs|AllowFileAccessFromFileURLs|JavaScriptCanOpenWindowsAutomatically)\(\s*true\s*\)`)
	rePrefs       = regexp.MustCompile(`getSharedPreferences\(\s*"([^"]+)"`)
	reNativeDecl  = regexp.MustCompile(`native\s+\w[\w<>\[\]]*\s+(\w+)\s*\(`)
	reDexLoad     = regexp.MustCompile(`(DexClassLoader|PathClassLoader|createPackageContext|loadClass)\(`)
	reQueryParam  = regexp.MustCompile(`getQueryParameter\(\s*"([^"]+)"`)
	reURL         = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}`)
)

// scanSources walks the jadx output and extracts code-level facts. Each call
// site records a file:line relative to the source root.
func (f *Facts) scanSources(sourceRoot string) {
	extraKeysByClass := map[string][]string{}
	appPrefix := strings.ReplaceAll(f.Package, ".", "/") + "/"
	readSources(sourceRoot, func(path, content string) {
		rel, _ := filepath.Rel(sourceRoot, path)
		// Scan the application's own classes for call sites and literals;
		// bundled libraries (androidx, tink, okio, firebase, gms) are not the
		// app's findings and only add noise.
		inApp := f.Package != "" && strings.HasPrefix(rel, appPrefix)
		class := strings.TrimSuffix(rel, ".java")
		class = strings.ReplaceAll(class, string(filepath.Separator), ".")
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			loc := func() string { return rel + ":" + itoa(i+1) }
			if !inApp {
				// Outside the app package, only intent extras (receivers may live
				// in libraries the app invokes) and nothing else is collected.
				for _, m := range reGetExtra.FindAllStringSubmatch(line, -1) {
					extraKeysByClass[class] = append(extraKeysByClass[class], m[1])
				}
				continue
			}
			if m := reCipher.FindStringSubmatch(line); m != nil {
				kind := "cipher"
				up := strings.ToUpper(m[1])
				if strings.Contains(up, "/ECB") || (!strings.Contains(up, "/") && (strings.HasPrefix(up, "AES") || strings.HasPrefix(up, "DES"))) {
					kind = "cipher_ecb"
				}
				if strings.HasPrefix(up, "DES") || strings.HasPrefix(up, "RC4") {
					kind = "cipher_weak"
				}
				f.CryptoCallSites = append(f.CryptoCallSites, CallSite{Kind: kind, Detail: m[1], Location: loc()})
			}
			if reSecretKey.MatchString(line) {
				f.CryptoCallSites = append(f.CryptoCallSites, CallSite{Kind: "secret_key_spec", Detail: strings.TrimSpace(line), Location: loc()})
			}
			if m := reKeyLiteral.FindStringSubmatch(line); m != nil && looksLikeKey(m[1]) {
				f.CryptoCallSites = append(f.CryptoCallSites, CallSite{Kind: "hardcoded_key", Detail: "key literal length " + itoa(len(m[1])), Location: loc()})
				f.Secrets = append(f.Secrets, Secret{Kind: "crypto_key", Value: m[1], Location: loc()})
			}
			if m := reMD5.FindStringSubmatch(line); m != nil {
				f.CryptoCallSites = append(f.CryptoCallSites, CallSite{Kind: "weak_hash", Detail: m[1], Location: loc()})
			}
			if reRandom.MatchString(line) {
				f.CryptoCallSites = append(f.CryptoCallSites, CallSite{Kind: "insecure_random", Detail: "java.util.Random", Location: loc()})
			}
			for _, m := range reGetExtra.FindAllStringSubmatch(line, -1) {
				extraKeysByClass[class] = append(extraKeysByClass[class], m[1])
			}
			for _, m := range rePutExtra.FindAllStringSubmatch(line, -1) {
				extraKeysByClass[class] = append(extraKeysByClass[class], m[1])
			}
			if m := reAddURI.FindStringSubmatch(line); m != nil {
				f.ProviderPaths = append(f.ProviderPaths, m[1]+"/"+m[2])
			}
			if m := reJSInterface.FindStringSubmatch(line); m != nil {
				f.JSInterfaces = append(f.JSInterfaces, m[1])
			}
			if m := reWebSetting.FindStringSubmatch(line); m != nil {
				f.WebViewFlags = append(f.WebViewFlags, m[1])
			}
			if m := rePrefs.FindStringSubmatch(line); m != nil {
				f.PrefsNames = append(f.PrefsNames, m[1])
			}
			if m := reNativeDecl.FindStringSubmatch(line); m != nil {
				f.NativeMethods = append(f.NativeMethods, m[1])
			}
			if reDexLoad.MatchString(line) {
				f.DynamicCodeLoads = append(f.DynamicCodeLoads, CallSite{Kind: "dynamic_code_load", Detail: clip(strings.TrimSpace(line), 160), Location: loc()})
			}
			for _, m := range reQueryParam.FindAllStringSubmatch(line, -1) {
				f.attachQueryKey(class, m[1])
			}
			for _, m := range reURL.FindAllString(line, -1) {
				if !strings.Contains(m, "schemas.android.com") && !strings.Contains(m, "w3.org") {
					f.URLs = append(f.URLs, strings.TrimRight(m, ".,;)}\"'"))
				}
			}
		}
	})
	// Attach extra keys to their components by class-name match.
	for i := range f.Components {
		name := f.Components[i].Name
		for class, keys := range extraKeysByClass {
			if class == name || strings.HasSuffix(class, "."+shortName(name)) || strings.HasSuffix(name, "."+shortName(class)) {
				f.Components[i].ExtraKeys = dedupe(append(f.Components[i].ExtraKeys, keys...))
			}
		}
	}
	f.CryptoCallSites = dedupeCallSites(f.CryptoCallSites)
	f.DynamicCodeLoads = dedupeCallSites(f.DynamicCodeLoads)
	f.JSInterfaces = dedupe(f.JSInterfaces)
	f.WebViewFlags = dedupe(f.WebViewFlags)
	f.ProviderPaths = dedupe(f.ProviderPaths)
	f.PrefsNames = dedupe(f.PrefsNames)
	f.NativeMethods = dedupe(f.NativeMethods)
	f.URLs = dedupe(f.URLs)
	f.Secrets = dedupeSecrets(f.Secrets)
}

func (f *Facts) attachQueryKey(class, key string) {
	for i := range f.DeepLinks {
		dlClass := shortName(f.DeepLinks[i].Activity)
		if dlClass != "" && (strings.HasSuffix(class, dlClass) || strings.Contains(class, dlClass)) {
			f.DeepLinks[i].QueryKeys = dedupe(append(f.DeepLinks[i].QueryKeys, key))
			return
		}
	}
	// Unmatched keys attach to every deep link as candidates.
	for i := range f.DeepLinks {
		f.DeepLinks[i].QueryKeys = dedupe(append(f.DeepLinks[i].QueryKeys, key))
	}
}

func shortName(fqn string) string {
	if i := strings.LastIndexByte(fqn, '.'); i >= 0 {
		return fqn[i+1:]
	}
	return fqn
}

func looksLikeKey(s string) bool {
	if len(s) < 8 || strings.Contains(s, " ") || strings.HasPrefix(s, "http") {
		return false
	}
	letters, digits := 0, 0
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
			letters++
		case r >= '0' && r <= '9':
			digits++
		}
	}
	return letters > 0 && (digits > 0 || len(s) == 16 || len(s) == 24 || len(s) == 32)
}

func dedupeCallSites(cs []CallSite) []CallSite {
	seen := map[string]bool{}
	out := []CallSite{}
	for _, c := range cs {
		k := c.Kind + "|" + c.Location
		if !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	}
	return out
}

func dedupeSecrets(ss []Secret) []Secret {
	seen := map[string]bool{}
	out := []Secret{}
	for _, s := range ss {
		k := s.Kind + "|" + s.Value
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
