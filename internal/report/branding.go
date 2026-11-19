package report

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
)

// Branding holds the firm-specific look of the templated VAPT document. It is
// loaded at runtime from an assets directory (report_assets/) that is kept out
// of git, so no client template ships with the code. When the directory or any
// field is absent the document still renders with neutral defaults.
type Branding struct {
	CompanyName string        `json:"company_name"`
	CoverTitle  string        `json:"cover_title"`
	AccentColor string        `json:"accent_color"`
	Summary     string        `json:"summary"`
	Appendix    []SeverityDef `json:"appendix"`

	// Logo/CoverBackground name image files inside the assets dir; resolved to
	// data URIs in LogoDataURI/CoverDataURI so the rendered HTML is self-contained.
	Logo            string `json:"logo"`
	CoverBackground string `json:"cover_background"`

	LogoDataURI  string `json:"-"`
	CoverDataURI string `json:"-"`
}

// SeverityDef is one row of the Appendix severity-and-risk matrix.
type SeverityDef struct {
	Severity   string `json:"severity"`
	Definition string `json:"definition"`
}

// defaultCoverTitle is used when branding.json is missing or omits the title.
const defaultCoverTitle = "Vulnerability Assessment & Penetration Testing (VAPT) Report"

// LoadBranding reads <dir>/branding.json and inlines its images. A missing dir
// or file yields neutral defaults (no logo, generic title) rather than an error,
// so the export works on a checkout that has no firm assets.
func LoadBranding(dir string) Branding {
	b := Branding{}
	if data, err := os.ReadFile(filepath.Join(dir, "branding.json")); err == nil {
		_ = json.Unmarshal(data, &b)
	}
	if b.CoverTitle == "" {
		b.CoverTitle = defaultCoverTitle
	}
	if b.AccentColor == "" {
		b.AccentColor = "#c0392b"
	}
	b.LogoDataURI = imageDataURI(dir, b.Logo)
	b.CoverDataURI = imageDataURI(dir, b.CoverBackground)
	return b
}

// imageDataURI reads an image file in dir and returns a base64 data URI, or ""
// when name is empty or unreadable.
func imageDataURI(dir, name string) string {
	if name == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	mime := "image/png"
	if ext := filepath.Ext(name); ext == ".jpg" || ext == ".jpeg" {
		mime = "image/jpeg"
	}
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
}
