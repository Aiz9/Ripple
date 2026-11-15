package androidapk

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func apkEntries(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for name, data := range entries {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.apk")
	if err := os.WriteFile(path, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestReferencedNetworkConfiguration(t *testing.T) {
	manifest := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.app"><application android:networkSecurityConfig="@xml/network"/></manifest>`)
	for _, malformed := range []bool{false, true} {
		t.Run(map[bool]string{true: "malformed", false: "valid"}[malformed], func(t *testing.T) {
			config := []byte(`<network-security-config><base-config cleartextTrafficPermitted="false"/><domain-config cleartextTrafficPermitted="true"/><debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides></network-security-config>`)
			if malformed {
				config = []byte(`<network-security-config><`)
			}
			r, err := Analyze(apkEntries(t, map[string][]byte{"AndroidManifest.xml": manifest, "res/xml/network.xml": config}))
			if err != nil {
				t.Fatal(err)
			}
			if malformed {
				if len(r.NetworkConfig) != 0 || !strings.Contains(strings.Join(r.Warnings, " "), "Malformed") {
					t.Fatal("malformed config accepted")
				}
				return
			}
			if len(r.NetworkConfig) != 3 || !r.NetworkConfig[2].DebugOnly || r.NetworkConfig[2].TrustSource != "user" {
				t.Fatal(r.NetworkConfig)
			}
			for _, f := range r.Findings {
				if f.Status == "validated" {
					t.Fatal("declaration became confirmed vulnerability")
				}
			}
		})
	}
}
func certificateFixture(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "authorized-test"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(2000000000, 0)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
func TestJARCertificateMetadata(t *testing.T) {
	der := certificateFixture(t)
	emptySeq := asn1.RawValue{Class: 0, Tag: 16, IsCompound: true}
	signed, err := asn1.Marshal(struct {
		Version      int
		Algorithms   asn1.RawValue
		Content      asn1.RawValue
		Certificates asn1.RawValue
	}{1, asn1.RawValue{Tag: 17, IsCompound: true}, emptySeq, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der}})
	if err != nil {
		t.Fatal(err)
	}
	container, err := asn1.Marshal(struct {
		Type asn1.ObjectIdentifier
		Body asn1.RawValue
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: signed}})
	if err != nil {
		t.Fatal(err)
	}
	path := apkEntries(t, map[string][]byte{"AndroidManifest.xml": []byte(`<manifest package="example.app"><application/></manifest>`), "META-INF/CERT.RSA": container})
	r, err := Analyze(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Certificates) != 1 || r.Certificates[0].Serial != "42" || len(r.Certificates[0].SHA256) != 64 {
		t.Fatalf("metadata missing: %+v %v", r.Certificates, r.Warnings)
	}
}
func length32(b []byte) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}
func TestSchemeCertificateMetadataAndMalformedLengths(t *testing.T) {
	der := certificateFixture(t)
	signed := append(length32(nil), length32(length32(der))...)
	signer := length32(signed)
	data := length32(length32(signer))
	for _, scheme := range []string{"v2-container", "v3-container"} {
		r := &Report{}
		if err := parseSchemeCertificates(data, scheme, r); err != nil {
			t.Fatal(err)
		}
		if len(r.Certificates) != 1 || r.Certificates[0].Scheme != scheme {
			t.Fatal(r.Certificates)
		}
	}
	for _, bad := range [][]byte{nil, {255, 255, 255, 255}, data[:len(data)-1]} {
		if err := parseSchemeCertificates(bad, "v2-container", &Report{}); err == nil {
			t.Fatal("malformed lengths accepted")
		}
	}
}
