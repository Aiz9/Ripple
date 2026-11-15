package androidapk

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func dexURLFixture() []byte {
	strings := []string{"Lcom/example/app/Main;", "https://api.owned-app.test/profile", "https://sdk-reference.test/docs"}
	b := make([]byte, 256)
	copy(b, []byte("dex\n035\x00"))
	put := func(at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
	put(40, 0x12345678)
	put(56, 3)
	put(60, 112)
	put(64, 1)
	put(68, 124)
	put(96, 1)
	put(100, 128)
	put(124, 0)
	put(128, 0)
	put(152, 192)
	// One direct method, whose code starts at offset 208.
	copy(b[192:], []byte{0, 0, 1, 0, 0, 1, 0xd0, 1})
	put(220, 6)
	// A three-unit const instruction contains a fake const-string in its operand;
	// it must be skipped before the genuine two-unit const-string instruction.
	for i, v := range []uint16{0x0014, 0x001a, 0x0002, 0x001a, 0x0001, 0x000e} {
		binary.LittleEndian.PutUint16(b[224+i*2:], v)
	}
	for i, value := range strings {
		put(112+i*4, uint32(len(b)))
		b = append(b, byte(len(value)))
		b = append(b, []byte(value)...)
		b = append(b, 0)
	}
	put(32, uint32(len(b)))
	return b
}
func TestAPKDEXAttributionDoesNotScanInstructionOperands(t *testing.T) {
	urls := dexAppURLs(dexURLFixture(), "com.example.app")
	if urls["https://api.owned-app.test/profile"] != "com/example/app/Main" {
		t.Fatalf("application URL was not attributed: %+v", urls)
	}
	if _, ok := urls["https://sdk-reference.test/docs"]; ok {
		t.Fatal("instruction operand was incorrectly interpreted as a URL reference")
	}
	if len(dexAppURLs(dexURLFixture(), "other.package")) != 0 {
		t.Fatal("library classes were attributed to a different application")
	}
}
func TestAPKDiscoveryRetainsFirstPartyProvenance(t *testing.T) {
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	f, _ := w.Create("classes.dex")
	_, _ = f.Write(dexURLFixture())
	_ = w.Close()
	path := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(path, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	urls, _, err := DiscoverApplicationURLs(path, "com.example.app")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range urls {
		if u.URL == "https://api.owned-app.test/profile" && u.Owner == "" {
			t.Fatal("own-class provenance lost")
		}
		if u.URL == "https://sdk-reference.test/docs" && u.Owner != "" {
			t.Fatal("unreferenced pool string became an automatic app target")
		}
	}
}
func FuzzDEXURLAttribution(f *testing.F) {
	f.Add(dexURLFixture())
	f.Add([]byte("dex\n035\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8<<20 {
			t.Skip()
		}
		_ = dexAppURLs(data, "com.example.app")
	})
}
