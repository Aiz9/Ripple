package androidapk

import (
	"archive/zip"
	"bytes"
	"testing"
)

func createTestZip(entries map[string][]byte) *zip.Reader {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	for name, content := range entries {
		f, _ := w.Create(name)
		_, _ = f.Write(content)
	}
	_ = w.Close()
	r, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	return r
}

func TestInspectFlutterNonFlutter(t *testing.T) {
	z := createTestZip(map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest></manifest>"),
		"classes.dex":         []byte("dex\n035\x00"),
	})
	rep, err := InspectFlutter(z)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.IsFlutter {
		t.Errorf("expected IsFlutter=false, got true")
	}
}

func TestInspectFlutterAOT(t *testing.T) {
	fakeLibApp := []byte("\x7fELFfakecontenthttps://api.banking.example.com/v1/transfer\x00api_key=\"secret-token-12345678\"\x00plugins.flutter.io/methods\x00")
	z := createTestZip(map[string][]byte{
		"AndroidManifest.xml":                      []byte("<manifest></manifest>"),
		"lib/arm64-v8a/libflutter.so":              []byte("flutter-engine-commit-1234567890123456789012345678901234567890"),
		"lib/arm64-v8a/libapp.so":                  fakeLibApp,
		"assets/flutter_assets/AssetManifest.json": []byte("{}"),
		"assets/flutter_assets/ca-cert.pem":        []byte("-----BEGIN CERTIFICATE-----"),
	})

	rep, err := InspectFlutter(z)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rep.IsFlutter {
		t.Fatalf("expected IsFlutter=true, got false")
	}
	if rep.BuildType != "AOT (Release/Profile)" {
		t.Errorf("expected BuildType='AOT (Release/Profile)', got %q", rep.BuildType)
	}
	if len(rep.BundledCerts) != 1 || rep.BundledCerts[0] != "ca-cert.pem" {
		t.Errorf("expected ca-cert.pem in BundledCerts, got %v", rep.BundledCerts)
	}
	if len(rep.DiscoveredURLs) == 0 || rep.DiscoveredURLs[0] != "https://api.banking.example.com/v1/transfer" {
		t.Errorf("expected discovered URL, got %v", rep.DiscoveredURLs)
	}
	if len(rep.PlatformChannels) == 0 || rep.PlatformChannels[0] != "plugins.flutter.io/methods" {
		t.Errorf("expected platform channel, got %v", rep.PlatformChannels)
	}
}

func TestInspectFlutterDebugJIT(t *testing.T) {
	z := createTestZip(map[string][]byte{
		"AndroidManifest.xml":                   []byte("<manifest></manifest>"),
		"lib/arm64-v8a/libflutter.so":           []byte("engine"),
		"assets/flutter_assets/kernel_blob.bin": []byte("dart bytecode"),
	})

	rep, err := InspectFlutter(z)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rep.IsFlutter {
		t.Fatalf("expected IsFlutter=true, got false")
	}
	if rep.BuildType != "JIT (Debug)" {
		t.Errorf("expected BuildType='JIT (Debug)', got %q", rep.BuildType)
	}
	hasFinding := false
	for _, f := range rep.SecurityFindings {
		if f.ID == "FLUTTER_DEBUG_BUILD_ARTIFACTS" {
			hasFinding = true
		}
	}
	if !hasFinding {
		t.Errorf("expected FLUTTER_DEBUG_BUILD_ARTIFACTS finding for JIT build")
	}
}
