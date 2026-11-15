package androidapk

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func TestAPKArchivePreflightRejectsForgedMetadata(t *testing.T) {
	p := testAPK(t, []byte(`<manifest package="com.example"><application/></manifest>`))
	original, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightAPK(bytes.NewReader(original), int64(len(original))); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(data []byte) {
			binary.LittleEndian.PutUint16(data[len(data)-22+8:], 0)
			binary.LittleEndian.PutUint16(data[len(data)-22+10:], 0)
		},
		func(data []byte) { binary.LittleEndian.PutUint16(data[len(data)-22+4:], 1) },
		func(data []byte) { binary.LittleEndian.PutUint32(data[len(data)-22+12:], 0xffffffff) },
		func(data []byte) { binary.LittleEndian.PutUint32(data[len(data)-22+16:], 0) },
	} {
		data := append([]byte{}, original...)
		mutate(data)
		if err := preflightAPK(bytes.NewReader(data), int64(len(data))); err == nil {
			t.Fatal("forged central directory accepted")
		}
	}
}
