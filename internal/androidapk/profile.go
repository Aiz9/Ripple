package androidapk

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/internal/mobiletest"
)

// inspectProfile reads bounded prefixes without extracting or executing APK code.
// Markers establish only bundled technology/indicators, never vulnerable behavior.
func inspectProfile(z *zip.Reader, app *element, report *Report) mobiletest.Profile {
	p := mobiletest.Profile{Technologies: []mobiletest.Technology{}, ManifestFlags: map[string]string{}, DeepLinks: []string{}, DebugArtifacts: []string{}, Signals: map[string][]string{}, Limitations: []string{
		"Technology markers may belong to bundled dependencies; they do not prove the language of first-party business logic.",
		"Engine/dependency versions, signature validity, obfuscation flags and security-sensitive code paths require external tooling or build provenance.",
		"Indicator scan: at most 16 MiB per eligible entry, 64 MiB total; encrypted, compressed-within-entry and dynamically loaded code may be missed.",
	}}
	for _, key := range []string{"debuggable", "testOnly", "allowBackup", "usesCleartextTraffic", "networkSecurityConfig", "fullBackupContent", "dataExtractionRules"} {
		value := app.attr(key)
		if value == "" {
			value = "omitted; platform/SDK defaults apply"
		}
		p.ManifestFlags[key] = value
	}
	for _, component := range app.children {
		for _, filter := range component.children {
			if filter.name != "intent-filter" {
				continue
			}
			for _, data := range filter.children {
				if data.name != "data" || len(p.DeepLinks) >= 200 {
					continue
				}
				p.DeepLinks = append(p.DeepLinks, fmt.Sprintf("component=%s scheme=%s host=%s path=%s pathPrefix=%s pathPattern=%s autoVerify=%s", component.attr("name"), data.attr("scheme"), data.attr("host"), data.attr("path"), data.attr("pathPrefix"), data.attr("pathPattern"), filter.attr("autoVerify")))
			}
		}
	}
	technologies := map[string]*mobiletest.Technology{}
	addTech := func(id, name, evidence string) {
		if technologies[id] == nil {
			technologies[id] = &mobiletest.Technology{ID: id, Name: name, Evidence: []string{}}
		}
		t := technologies[id]
		if len(t.Evidence) < 12 {
			t.Evidence = append(t.Evidence, evidence)
		}
	}
	addSignal := func(id, evidence string) {
		if len(p.Signals[id]) < 24 {
			p.Signals[id] = append(p.Signals[id], evidence)
		}
	}
	markers := []struct{ signal, text string }{
		{"apk_pinning", "CertificatePinner"}, {"apk_pinning", "checkServerTrusted"}, {"apk_pinning", "badCertificateCallback"}, {"apk_pinning", "TrustManager"},
		{"apk_storage", "flutter_secure_storage"}, {"apk_storage", "EncryptedSharedPreferences"}, {"apk_storage", "AndroidKeyStore"}, {"apk_storage", "shared_preferences"}, {"apk_storage", "net/sqlcipher"}, {"apk_storage", "AsyncStorage"},
		{"apk_channels", "MethodChannel"}, {"apk_channels", "EventChannel"}, {"apk_channels", "JavascriptInterface"}, {"apk_channels", "ReactContextBaseJavaModule"}, {"apk_channels", "CordovaPlugin"}, {"apk_channels", "CapacitorPlugin"}, {"apk_channels", "JNI_OnLoad"},
		{"apk_crypto", "AES/ECB"}, {"apk_crypto", "DES/"}, {"apk_crypto", "pointycastle"}, {"apk_crypto", "javax/crypto"}, {"apk_crypto", "System.Security.Cryptography"}, {"apk_crypto", "crypto-js"},
		{"apk_random", "java/util/Random"}, {"apk_random", "java/security/SecureRandom"}, {"apk_random", "Random.secure"}, {"apk_random", "Math.random"}, {"apk_random", "RAND_bytes"},
		{"apk_webview", "setJavaScriptEnabled"}, {"apk_webview", "addJavascriptInterface"}, {"apk_webview", "setAllowUniversalAccessFromFileURLs"},
		{"apk_dependencies", "com/google/firebase"}, {"apk_dependencies", "com/adjust/sdk"}, {"apk_dependencies", "com/appsflyer"}, {"apk_dependencies", "com/stripe"}, {"apk_dependencies", "sentry"}, {"apk_dependencies", "Crashlytics"},
		{"apk_secrets", "-----BEGIN PRIVATE KEY-----"}, {"apk_secrets", "-----BEGIN RSA PRIVATE KEY-----"}, {"apk_secrets", "-----BEGIN EC PRIVATE KEY-----"},
	}
	remaining := int64(64 << 20)
	for _, entry := range z.File {
		name := strings.ToLower(entry.Name)
		if strings.HasSuffix(name, ".dex") {
			addTech("jvm", "Android DEX (Java/Kotlin and JVM libraries)", entry.Name)
		}
		if strings.HasPrefix(name, "lib/") && strings.HasSuffix(name, ".so") {
			addTech("native", "Native ELF libraries (source language unverified)", entry.Name)
		}
		if strings.HasSuffix(name, "/libflutter.so") || strings.HasPrefix(name, "assets/flutter_assets/") {
			addTech("flutter", "Flutter / Dart", entry.Name)
		}
		if strings.HasSuffix(name, "/libapp.so") && strings.HasPrefix(name, "lib/") {
			addSignal("apk_assets", entry.Name+": possible Dart AOT image; verify together with Flutter engine")
		}
		if strings.Contains(name, "libhermes") || strings.HasSuffix(name, "index.android.bundle") {
			addTech("react_native", "React Native / JavaScript or Hermes", entry.Name)
		}
		if strings.HasSuffix(name, "cordova.js") {
			addTech("cordova", "Cordova / web hybrid", entry.Name)
		}
		if strings.Contains(name, "capacitor.config") || strings.HasSuffix(name, "capacitor.plugins.json") {
			addTech("capacitor", "Capacitor / web hybrid", entry.Name)
		}
		if strings.HasPrefix(name, "assemblies/") || strings.Contains(name, "libmonodroid") || strings.Contains(name, "libmonosgen") {
			addTech("dotnet", ".NET / Xamarin / MAUI", entry.Name)
		}
		if strings.HasSuffix(name, "/libunity.so") || strings.HasSuffix(name, "/libil2cpp.so") {
			addTech("unity", "Unity / managed or IL2CPP", entry.Name)
		}
		if strings.HasSuffix(name, "kernel_blob.bin") || strings.HasSuffix(name, ".js.map") || strings.HasSuffix(name, ".bundle.map") || strings.HasSuffix(name, "/vm_snapshot_data") {
			if len(p.DebugArtifacts) < 100 {
				p.DebugArtifacts = append(p.DebugArtifacts, entry.Name)
			}
		}
		eligible := false
		for _, ext := range []string{".dex", ".so", ".js", ".bundle", ".json", ".xml", ".properties", ".dll"} {
			if strings.HasSuffix(name, ext) {
				eligible = true
			}
		}
		if !eligible {
			continue
		}
		if remaining <= 0 {
			p.Truncated = true
			continue
		}
		limit := int64(16 << 20)
		if remaining < limit {
			limit = remaining
		}
		reader, err := entry.Open()
		if err != nil {
			p.Truncated = true
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, limit))
		_ = reader.Close()
		remaining -= int64(len(data))
		p.BytesInspected += int64(len(data))
		if readErr != nil || uint64(len(data)) < entry.UncompressedSize64 {
			p.Truncated = true
		}
		if bytes.Contains(data, []byte("Lkotlin/Metadata;")) {
			addTech("kotlin", "Kotlin metadata (may be library code)", entry.Name)
		}
		if bytes.Contains(data, []byte("Landroidx/compose/")) {
			addTech("compose", "Jetpack Compose references", entry.Name)
		}
		if bytes.Contains(data, []byte("Lcom/facebook/react/")) {
			addTech("react_native", "React Native / JavaScript or Hermes", entry.Name)
		}
		for _, marker := range markers {
			if bytes.Contains(data, []byte(marker.text)) {
				addSignal(marker.signal, entry.Name+": marker "+marker.text+" (reference only)")
			}
		}
	}
	for _, t := range technologies {
		sort.Strings(t.Evidence)
		p.Technologies = append(p.Technologies, *t)
	}
	sort.Slice(p.Technologies, func(i, j int) bool { return p.Technologies[i].ID < p.Technologies[j].ID })
	sort.Strings(p.DeepLinks)
	sort.Strings(p.DebugArtifacts)
	if p.Truncated {
		p.Limitations = append(p.Limitations, "At least one entry was not completely inspected or could not be read; marker absence has no coverage meaning.")
	}
	return p
}
