package server

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/internal/db"
)

func TestFindingsZIPKeepsLongChineseNamesValidAndUnique(t *testing.T) {
	findings := []*db.DBFinding{
		{ID: 1, Name: strings.Repeat("\u767b\u5f55\u4ed8\u6b3e\u6d41\u7a0b", 30), Severity: "high"},
		{ID: 2, Name: strings.Repeat("\u767b\u5f55\u4ed8\u6b3e\u6d41\u7a0b", 30), Severity: "high"},
	}
	var output bytes.Buffer
	if err := writeFindingsEvidenceZip(&output, findings, t.TempDir(), time.Now()); err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.File) != len(findings) {
		t.Fatalf("unexpected ZIP entries: %d", len(archive.File))
	}
	seen := map[string]bool{}
	for _, entry := range archive.File {
		if !utf8.ValidString(entry.Name) || seen[entry.Name] || strings.ContainsAny(entry.Name, "/\\") {
			t.Fatalf("invalid or duplicate ZIP entry: %q", entry.Name)
		}
		seen[entry.Name] = true
		reader, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || !bytes.Contains(body, []byte(findings[0].Name)) {
			t.Fatalf("filename truncation damaged the report body: %v", err)
		}
	}
}
