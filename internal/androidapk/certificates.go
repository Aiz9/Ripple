package androidapk

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

type CertificateMetadata struct {
	Scheme             string    `json:"scheme"`
	SHA256             string    `json:"sha256"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	Serial             string    `json:"serial"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
}

func addCertificate(r *Report, scheme string, der []byte) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(hash[:])
	for _, c := range r.Certificates {
		if c.SHA256 == fingerprint && c.Scheme == scheme {
			return nil
		}
	}
	if len(r.Certificates) >= 64 {
		return fmt.Errorf("certificate count limit")
	}
	r.Certificates = append(r.Certificates, CertificateMetadata{scheme, fingerprint, cert.Subject.String(), cert.Issuer.String(), cert.SerialNumber.String(), cert.NotBefore, cert.NotAfter, cert.PublicKeyAlgorithm.String(), cert.SignatureAlgorithm.String()})
	return nil
}

// PKCS#7 SignedData embeds a certificate set. Parse DER certificates with Go's
// X.509 parser; this extracts metadata and does NOT verify the JAR signature.
func parseJARCertificates(data []byte, r *Report) error {
	var content struct {
		Type asn1.ObjectIdentifier
		Body asn1.RawValue `asn1:"explicit,tag:0"`
	}
	rest, err := asn1.Unmarshal(data, &content)
	if err != nil || len(rest) != 0 || !content.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return fmt.Errorf("invalid PKCS7 SignedData")
	}
	var signed struct {
		Version      int
		Algorithms   asn1.RawValue
		Content      asn1.RawValue
		Certificates asn1.RawValue `asn1:"optional,tag:0"`
	}
	if _, err = asn1.Unmarshal(content.Body.Bytes, &signed); err != nil {
		return err
	}
	certs := signed.Certificates.Bytes
	if len(certs) == 0 {
		return fmt.Errorf("no certificates in SignedData")
	}
	for len(certs) > 0 {
		var cert asn1.RawValue
		certs, err = asn1.Unmarshal(certs, &cert)
		if err != nil {
			return err
		}
		if err = addCertificate(r, "v1-container", cert.FullBytes); err != nil {
			return err
		}
	}
	return nil
}
func takeLength32(data *[]byte) ([]byte, error) {
	if len(*data) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	n := uint64(binary.LittleEndian.Uint32(*data))
	*data = (*data)[4:]
	if n > uint64(len(*data)) {
		return nil, io.ErrUnexpectedEOF
	}
	value := (*data)[:int(n)]
	*data = (*data)[int(n):]
	return value, nil
}
func parseSchemeCertificates(data []byte, scheme string, r *Report) error {
	signers, err := takeLength32(&data)
	if err != nil || len(data) != 0 {
		return fmt.Errorf("invalid signer sequence")
	}
	for len(signers) > 0 {
		signer, err := takeLength32(&signers)
		if err != nil {
			return err
		}
		signed, err := takeLength32(&signer)
		if err != nil {
			return err
		}
		if _, err = takeLength32(&signed); err != nil {
			return err
		} // digests
		certs, err := takeLength32(&signed)
		if err != nil {
			return err
		}
		for len(certs) > 0 {
			der, err := takeLength32(&certs)
			if err != nil {
				return err
			}
			if err = addCertificate(r, scheme, der); err != nil {
				return err
			}
		}
	}
	return nil
}
func inspectCertificates(file io.ReaderAt, size int64, z *zip.Reader, r *Report) {
	for _, entry := range z.File {
		name := strings.ToUpper(entry.Name)
		if !strings.HasPrefix(name, "META-INF/") || !(strings.HasSuffix(name, ".RSA") || strings.HasSuffix(name, ".DSA") || strings.HasSuffix(name, ".EC")) {
			continue
		}
		data, err := boundedEntry(entry, 4<<20)
		if err == nil {
			err = parseJARCertificates(data, r)
		}
		if err != nil {
			r.Warnings = append(r.Warnings, "Signing certificate container could not be parsed: "+entry.Name)
		}
	}
	// The signing-block footer immediately precedes the ZIP central directory.
	length := size
	if length > 65557 {
		length = 65557
	}
	tail := make([]byte, int(length))
	if _, err := file.ReadAt(tail, size-length); err != nil {
		return
	}
	for off := len(tail) - 22; off >= 0; off-- {
		if !bytes.Equal(tail[off:off+4], []byte{'P', 'K', 5, 6}) || off+22+int(binary.LittleEndian.Uint16(tail[off+20:])) != len(tail) {
			continue
		}
		central := int64(binary.LittleEndian.Uint32(tail[off+16:]))
		if central < 24 {
			break
		}
		footer := make([]byte, 24)
		if _, err := file.ReadAt(footer, central-24); err != nil {
			break
		}
		if string(footer[8:]) != "APK Sig Block 42" {
			break
		}
		blockSize := binary.LittleEndian.Uint64(footer)
		if blockSize < 24 || blockSize > 16<<20 || blockSize+8 > uint64(central) {
			r.Warnings = append(r.Warnings, "Malformed or oversized APK signing block")
			break
		}
		block := make([]byte, int(blockSize)+8)
		if _, err := file.ReadAt(block, central-int64(len(block))); err != nil {
			break
		}
		if binary.LittleEndian.Uint64(block) != blockSize {
			r.Warnings = append(r.Warnings, "APK signing block length mismatch")
			break
		}
		pairs := block[8 : len(block)-24]
		for len(pairs) > 0 {
			if len(pairs) < 8 {
				r.Warnings = append(r.Warnings, "Truncated signing-block pair")
				break
			}
			n := binary.LittleEndian.Uint64(pairs)
			pairs = pairs[8:]
			if n < 4 || n > uint64(len(pairs)) {
				r.Warnings = append(r.Warnings, "Invalid signing-block pair length")
				break
			}
			value := pairs[:int(n)]
			pairs = pairs[int(n):]
			scheme := ""
			switch binary.LittleEndian.Uint32(value) {
			case 0x7109871a:
				scheme = "v2-container"
			case 0xf05368c0:
				scheme = "v3-container"
			}
			if scheme != "" {
				if err := parseSchemeCertificates(value[4:], scheme, r); err != nil {
					r.Warnings = append(r.Warnings, "Malformed "+scheme+" certificate metadata")
				}
			}
		}
		break
	}
	r.Warnings = append(r.Warnings, "Certificate metadata does not verify APK signatures, signer trust, rotation, or installability. v4 sidecars are not inspected.")
}
