package devicelab

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/internal/staticx"
)

func TestApplicableBypassesFlutterByLib(t *testing.T) {
	f := &staticx.Facts{NativeLibs: []string{"lib/x86_64/libflutter.so", "lib/arm64-v8a/libapp.so"}}
	got := ApplicableBypasses(f, nil)
	if !containsID(got, "flutter.boringssl.verify_cert_chain") {
		t.Fatalf("libflutter.so present but flutter bypass not selected: %v", ids(got))
	}
}

func TestApplicableBypassesBySourceSignal(t *testing.T) {
	got := ApplicableBypasses(&staticx.Facts{}, []string{"OkHttpPinning:okhttp3.CertificatePinner", "RootBeer:isRooted"})
	if !containsID(got, "okhttp.certificate_pinner") {
		t.Fatalf("CertificatePinner signal present but okhttp bypass not selected: %v", ids(got))
	}
	if !containsID(got, "rootbeer") {
		t.Fatalf("RootBeer signal present but rootbeer bypass not selected: %v", ids(got))
	}
}

func TestGenerateFridaBypassScriptFlutter(t *testing.T) {
	b, _ := BypassByID("flutter.boringssl.verify_cert_chain")
	js := GenerateFridaBypassScript([]Bypass{b})
	for _, want := range []string{
		"libflutter.so",
		"4c 89 cd 4d 89 c5 49 89 ce 49 89 d4 48 89 f3 49 89 ff", // the RE-derived fingerprint
		"ssl_bypass_applied",
		"retval.replace(0x1)",
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("generated script missing %q", want)
		}
	}
	assertValidJS(t, js)
}

func TestGenerateFridaBypassScriptJavaHooks(t *testing.T) {
	var all []Bypass
	for _, id := range []string{"okhttp.certificate_pinner", "conscrypt.trustmanager", "rootbeer"} {
		if b, ok := BypassByID(id); ok {
			all = append(all, b)
		}
	}
	js := GenerateFridaBypassScript(all)
	for _, want := range []string{"okhttp3.CertificatePinner", "com.scottyab.rootbeer.RootBeer", "Java.perform"} {
		if !strings.Contains(js, want) {
			t.Fatalf("generated script missing %q", want)
		}
	}
	assertValidJS(t, js)
}

func assertValidJS(t *testing.T, js string) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node unavailable; skipping JS syntax check")
	}
	f, err := os.CreateTemp(t.TempDir(), "bypass-*.js")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(js); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if out, err := exec.Command(node, "--check", f.Name()).CombinedOutput(); err != nil {
		t.Fatalf("generated JS is not valid: %v\n%s\n---\n%s", err, out, js)
	}
}

func containsID(bs []Bypass, id string) bool {
	for _, b := range bs {
		if b.ID == id {
			return true
		}
	}
	return false
}
func ids(bs []Bypass) []string {
	var o []string
	for _, b := range bs {
		o = append(o, b.ID)
	}
	return o
}
