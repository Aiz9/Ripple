package androidapk

import (
	"archive/zip"
	"fmt"
	"io"
	"strings"
)

type ConfigurationObservation struct {
	File        string `json:"file"`
	Element     string `json:"element"`
	Cleartext   string `json:"cleartext,omitempty"`
	TrustSource string `json:"trust_source,omitempty"`
	DebugOnly   bool   `json:"debug_only"`
}

func boundedEntry(entry *zip.File, limit uint64) ([]byte, error) {
	if entry.UncompressedSize64 > limit {
		return nil, fmt.Errorf("entry exceeds inspection limit")
	}
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if uint64(len(data)) > limit {
		return nil, fmt.Errorf("entry exceeds inspection limit")
	}
	return data, err
}
func inspectNetworkConfiguration(z *zip.Reader, app *element, r *Report) []ConfigurationObservation {
	ref := app.attr("networkSecurityConfig")
	if ref == "" {
		return nil
	}
	if !strings.HasPrefix(ref, "@xml/") {
		r.Warnings = append(r.Warnings, "Network security configuration resource ID could not be resolved; no effective-policy conclusion is available.")
		return nil
	}
	name := strings.TrimPrefix(ref, "@xml/")
	if name == "" || strings.ContainsAny(name, "/\\.") {
		r.Warnings = append(r.Warnings, "Invalid network security configuration resource reference")
		return nil
	}
	result := []ConfigurationObservation{}
	files := 0
	for _, entry := range z.File {
		parts := strings.Split(entry.Name, "/")
		if len(parts) != 3 || parts[0] != "res" || !(parts[1] == "xml" || strings.HasPrefix(parts[1], "xml-")) || parts[2] != name+".xml" {
			continue
		}
		files++
		if files > 32 {
			r.Warnings = append(r.Warnings, "Network configuration variant limit reached")
			break
		}
		data, err := boundedEntry(entry, 4<<20)
		var root *element
		if err == nil {
			root, err = parseXMLRoot(data, "network-security-config")
		}
		if err != nil {
			r.Warnings = append(r.Warnings, "Malformed or oversized network security configuration: "+entry.Name)
			continue
		}
		var visit func(*element, bool)
		visit = func(e *element, debug bool) {
			debug = debug || e.name == "debug-overrides"
			if e.name == "base-config" || e.name == "domain-config" || e.name == "certificates" || e.name == "pin-set" {
				observation := ConfigurationObservation{File: entry.Name, Element: e.name, Cleartext: e.attrs["cleartextTrafficPermitted"], TrustSource: e.attrs["src"], DebugOnly: debug}
				result = append(result, observation)
				if observation.Cleartext == "true" || observation.TrustSource == "user" {
					r.Findings = append(r.Findings, Finding{ID: fmt.Sprintf("network-config-%d", len(result)), Title: "Review network security configuration", Severity: "info", Evidence: fmt.Sprintf("%s: %s cleartext=%s trustSource=%s debugOnly=%t", entry.Name, e.name, observation.Cleartext, observation.TrustSource, debug), Recommendation: "Review domain inheritance, resource qualifiers, debug build state and observed traffic before validating exposure.", Status: "review"})
				}
			}
			for _, child := range e.children {
				visit(child, debug)
			}
		}
		visit(root, false)
	}
	if files == 0 {
		r.Warnings = append(r.Warnings, "Referenced network security configuration XML is missing")
	}
	r.Warnings = append(r.Warnings, "Network configuration declarations are observations; qualifier selection and effective inherited runtime policy require verification.")
	return result
}
