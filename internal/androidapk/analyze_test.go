package androidapk

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testAPK(t *testing.T, manifest []byte) string {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"AndroidManifest.xml", manifest}, {"classes.dex", []byte("dex\n035\x00")}, {"lib/arm64-v8a/libexample.so", []byte("test")}} {
		f, err := w.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(path, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAPKPlainManifest(t *testing.T) {
	path := testAPK(t, []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test" android:versionName="1.0" android:versionCode="12"><uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35"/><uses-permission android:name="android.permission.INTERNET"/><application android:debuggable="true" android:allowBackup="false" android:usesCleartextTraffic="false"><activity android:name=".MainActivity" android:exported="true"/><provider android:name=".PrivateProvider"/></application></manifest>`))
	r, err := Analyze(path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Package != "com.example.test" || r.TargetSDK != "35" || r.VersionCode != "12" || len(r.SHA256) != 64 || r.DexFiles != 1 || len(r.NativeLibraries) != 1 {
		t.Fatalf("bad report: %+v", r)
	}
	if len(r.Findings) != 2 || r.Findings[0].ID != "debuggable" || r.Findings[1].Severity != "info" {
		t.Fatalf("bad findings: %+v", r.Findings)
	}
	if r.Components[0].Name != "com.example.test.MainActivity" || r.Components[1].Exported != "false (default)" {
		t.Fatalf("bad components: %+v", r.Components)
	}
}

// Build a resource XML fixture containing a UTF-8 pool, typed boolean and
// integer attributes, and fully qualified Android attribute namespaces.
func binaryManifestFixture() []byte {
	stringsPool := []string{"manifest", "package", "com.example.binary", "application", "debuggable", androidNS, "uses-sdk", "targetSdkVersion"}
	u16write := func(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
	u32write := func(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
	pool := make([]byte, 28+len(stringsPool)*4)
	u16write(pool, 0, 1)
	u16write(pool, 2, 28)
	u32write(pool, 8, uint32(len(stringsPool)))
	u32write(pool, 16, 0x100)
	u32write(pool, 20, uint32(len(pool)))
	start := len(pool)
	for i, s := range stringsPool {
		u32write(pool, 28+i*4, uint32(len(pool)-start))
		pool = append(pool, byte(len(s)), byte(len(s)))
		pool = append(pool, []byte(s)...)
		pool = append(pool, 0)
	}
	u32write(pool, 4, uint32(len(pool)))
	elementChunk := func(name uint32, attributes [][4]uint32) []byte {
		b := make([]byte, 36+20*len(attributes))
		u16write(b, 0, 0x102)
		u16write(b, 2, 16)
		u32write(b, 4, uint32(len(b)))
		u32write(b, 16, 0xffffffff)
		u32write(b, 20, name)
		u16write(b, 24, 20)
		u16write(b, 26, 20)
		u16write(b, 28, uint16(len(attributes)))
		for i, a := range attributes {
			p := 36 + i*20
			u32write(b, p, a[0])
			u32write(b, p+4, a[1])
			u32write(b, p+8, 0xffffffff)
			u16write(b, p+12, 8)
			b[p+15] = byte(a[2])
			u32write(b, p+16, a[3])
		}
		return b
	}
	endChunk := func(name uint32) []byte {
		b := make([]byte, 24)
		u16write(b, 0, 0x103)
		u16write(b, 2, 16)
		u32write(b, 4, 24)
		u32write(b, 16, 0xffffffff)
		u32write(b, 20, name)
		return b
	}
	data := make([]byte, 8)
	u16write(data, 0, 3)
	u16write(data, 2, 8)
	data = append(data, pool...)
	data = append(data, elementChunk(0, [][4]uint32{{0xffffffff, 1, 3, 2}})...)
	data = append(data, elementChunk(6, [][4]uint32{{5, 7, 0x10, 35}})...)
	data = append(data, endChunk(6)...)
	data = append(data, elementChunk(3, [][4]uint32{{5, 4, 0x12, 1}})...)
	data = append(data, endChunk(3)...)
	data = append(data, endChunk(0)...)
	u32write(data, 4, uint32(len(data)))
	return data
}

func TestAPKBinaryManifest(t *testing.T) {
	r, err := Analyze(testAPK(t, binaryManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	if r.Package != "com.example.binary" || r.TargetSDK != "35" || len(r.Findings) < 1 || r.Findings[0].ID != "debuggable" {
		t.Fatalf("bad binary report: %+v", r)
	}
}

func TestAPKExportDefaultsAndResources(t *testing.T) {
	for _, target := range []string{"16", "30", "35"} {
		r, err := Analyze(testAPK(t, []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example"><uses-sdk android:targetSdkVersion="`+target+`"/><application android:debuggable="@bool/debug" android:allowBackup="false"><activity android:name=".A"><intent-filter/></activity><provider android:name=".P"/></application></manifest>`)))
		if err != nil {
			t.Fatal(err)
		}
		if target == "16" && !strings.HasPrefix(r.Components[1].Exported, "true") {
			t.Fatal("legacy provider default lost")
		}
		if target == "35" && !strings.HasPrefix(r.Components[0].Exported, "missing") {
			t.Fatal("missing explicit exported value not surfaced")
		}
		for _, finding := range r.Findings {
			if finding.ID == "debuggable" {
				t.Fatal("resource reference reported as resolved")
			}
		}
		if len(r.Warnings) < 2 {
			t.Fatal("resource warning missing")
		}
	}
}

func TestAPKRejectsInvalidInputs(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("invalid"), []byte(`<manifest/>`), binaryManifestFixture()[:50], []byte(`<manifest><application></manifest>`)} {
		if _, err := Analyze(testAPK(t, data)); err == nil {
			t.Fatalf("accepted invalid manifest: %q", data)
		}
	}
	path := filepath.Join(t.TempDir(), "invalid.apk")
	_ = os.WriteFile(path, []byte("not zip"), 0600)
	if _, err := Analyze(path); err == nil {
		t.Fatal("accepted non-ZIP")
	}
}

func TestAPKUTF16PoolBounds(t *testing.T) {
	// A zero-length string whose two-byte terminator is truncated must not panic.
	pool := make([]byte, 35)
	binary.LittleEndian.PutUint16(pool[2:], 28)
	binary.LittleEndian.PutUint32(pool[8:], 1)
	binary.LittleEndian.PutUint32(pool[20:], 32)
	if _, err := decodeStringPool(pool); err == nil {
		t.Fatal("accepted truncated terminator")
	}
}

func FuzzAPKManifest(f *testing.F) {
	f.Add(binaryManifestFixture())
	f.Add([]byte(`<manifest package="com.example"><application/></manifest>`))
	f.Add([]byte{3, 0, 8, 0, 8, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseManifest(data) })
}
