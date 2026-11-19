package report

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// RenderDoc converts a self-contained HTML document to PDF or DOCX and returns
// the bytes plus the HTTP content type. "pdf" uses headless Chrome for faithful
// CSS rendering; "docx" uses LibreOffice (soffice). It returns an error naming
// the missing tool when the required converter is not installed.
func RenderDoc(ctx context.Context, htmlDoc []byte, format string) ([]byte, string, error) {
	dir, err := os.MkdirTemp("", "ripple-report-")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(dir)

	in := filepath.Join(dir, "report.html")
	if err := os.WriteFile(in, htmlDoc, 0o600); err != nil {
		return nil, "", err
	}

	switch format {
	case "pdf":
		out := filepath.Join(dir, "report.pdf")
		if err := renderPDF(ctx, in, out, dir); err != nil {
			return nil, "", err
		}
		data, err := os.ReadFile(out)
		return data, "application/pdf", err
	case "docx":
		out, err := renderDOCX(ctx, in, dir)
		if err != nil {
			return nil, "", err
		}
		data, err := os.ReadFile(out)
		return data, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", err
	default:
		return nil, "", fmt.Errorf("unsupported report format %q", format)
	}
}

func lookupAny(names ...string) (string, bool) {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p, true
		}
	}
	return "", false
}

func renderPDF(ctx context.Context, in, out, work string) error {
	chrome, ok := lookupAny("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")
	if !ok {
		return fmt.Errorf("PDF export needs Google Chrome or Chromium installed on the server")
	}
	cmd := exec.CommandContext(ctx, chrome,
		"--headless=new", "--disable-gpu", "--no-sandbox",
		"--no-pdf-header-footer",
		"--user-data-dir="+filepath.Join(work, "chrome-profile"),
		"--run-all-compositor-stages-before-draw",
		"--virtual-time-budget=5000",
		"--print-to-pdf="+out,
		"file://"+in,
	)
	if combined, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chrome pdf render failed: %v: %s", err, combined)
	}
	if fi, err := os.Stat(out); err != nil || fi.Size() == 0 {
		return fmt.Errorf("chrome produced no PDF output")
	}
	return nil
}

func renderDOCX(ctx context.Context, in, work string) (string, error) {
	soffice, ok := lookupAny("soffice", "libreoffice")
	if !ok {
		return "", fmt.Errorf("DOCX export needs LibreOffice (soffice) installed on the server")
	}
	profile := filepath.Join(work, "lo-profile")
	cmd := exec.CommandContext(ctx, soffice,
		"--headless", "--norestore",
		"--convert-to", "docx:MS Word 2007 XML", "--outdir", work,
		"-env:UserInstallation=file://"+profile,
		in,
	)
	if combined, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("libreoffice docx render failed: %v: %s", err, combined)
	}
	out := filepath.Join(work, "report.docx")
	if fi, err := os.Stat(out); err != nil || fi.Size() == 0 {
		return "", fmt.Errorf("libreoffice produced no DOCX output")
	}
	return out, nil
}
