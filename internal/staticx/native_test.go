package staticx

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestExtractPrintable(t *testing.T) {
	data := append([]byte{0x00, 0x01}, []byte("hello-world")...)
	data = append(data, 0x00, 0x02)
	data = append(data, []byte("short")...) // 5 < minLen 6, dropped
	got := extractPrintable(data, 6)
	if len(got) != 1 || got[0] != "hello-world" {
		t.Fatalf("extractPrintable=%v", got)
	}
}

func TestScanNativeStringsRecoversEndpointsAndSecrets(t *testing.T) {
	// Build an in-memory APK with a libapp.so carrying a backend URL, a Google API
	// key and a JWT embedded between non-printable bytes (as Dart AOT does).
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("lib/arm64-v8a/libapp.so")
	blob := []byte{0x7f, 'E', 'L', 'F', 0x00, 0x00}
	blob = append(blob, []byte("https://bankxp.example-bank.com/webbackend/v2/initial/data")...)
	blob = append(blob, 0x00, 0x00)
	blob = append(blob, []byte("AIzaSyA1234567890abcdefghijklmnopqrstuvx")...)
	blob = append(blob, 0x00)
	blob = append(blob, []byte("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig12345")...)
	w.Write(blob)
	zw.Close()

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	f := &Facts{}
	for _, file := range zr.File {
		f.scanNativeStrings(file, file.Name)
	}

	wantURL := "https://bankxp.example-bank.com/webbackend/v2/initial/data"
	if !containsStr(f.URLs, wantURL) {
		t.Fatalf("backend URL not recovered from libapp.so: %v", f.URLs)
	}
	var kinds []string
	for _, s := range f.Secrets {
		kinds = append(kinds, s.Kind)
	}
	if !containsStr(kinds, "api_key") || !containsStr(kinds, "jwt") {
		t.Fatalf("secrets not recovered from libapp.so: %v", kinds)
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
