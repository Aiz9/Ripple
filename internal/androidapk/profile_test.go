package androidapk

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestBundledTechnologyProfile(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	entries := map[string]string{
		"classes.dex":                 "Lkotlin/Metadata; Landroidx/compose/ Lcom/facebook/react/; CertificatePinner AndroidKeyStore MethodChannel AES/ECB java/util/Random",
		"lib/arm64-v8a/libflutter.so": "engine", "lib/arm64-v8a/libapp.so": "application", "assets/flutter_assets/kernel_blob.bin": "debug",
		"assets/index.android.bundle": "bundle", "assets/www/cordova.js": "cordova", "assets/capacitor.config.json": "{}",
		"assemblies/Example.dll": "System.Security.Cryptography", "lib/arm64-v8a/libil2cpp.so": "native",
	}
	for name, data := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	p := inspectProfile(z, &element{}, &Report{})
	found := map[string]bool{}
	for _, tech := range p.Technologies {
		found[tech.ID] = true
		if len(tech.Evidence) == 0 {
			t.Fatal("missing provenance")
		}
	}
	for _, id := range []string{"jvm", "native", "flutter", "kotlin", "compose", "react_native", "cordova", "capacitor", "dotnet", "unity"} {
		if !found[id] {
			t.Fatalf("missed %s", id)
		}
	}
	for _, signal := range []string{"apk_pinning", "apk_storage", "apk_channels", "apk_crypto", "apk_random", "apk_assets"} {
		if len(p.Signals[signal]) == 0 {
			t.Fatalf("missed indicator %s", signal)
		}
	}
	if len(p.DebugArtifacts) != 1 || p.BytesInspected == 0 || len(p.Limitations) == 0 {
		t.Fatalf("missing limits/provenance: %+v", p)
	}
}
