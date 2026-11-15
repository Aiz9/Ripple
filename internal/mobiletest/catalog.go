// Package mobiletest defines the versioned assessment procedures. Catalog membership
// is not a claim of automated implementation or successful execution.
package mobiletest

import (
	_ "embed"
	"encoding/json"
)

//go:embed catalog.json
var catalogJSON []byte

const Version = "2026-11-06.1"

type Control struct {
	ID        string   `json:"id"`
	Section   string   `json:"section"`
	Title     string   `json:"title"`
	Objective string   `json:"objective"`
	Layer     string   `json:"layer"`
	MASVS     []string `json:"masvs"`
	CWE       []string `json:"cwe"`
	Signals   []string `json:"signals"`
	Requires  []string `json:"requires"`
	Procedure string   `json:"procedure"`
}

func Catalog() []Control {
	var out []Control
	if err := json.Unmarshal(catalogJSON, &out); err != nil {
		panic(err)
	}
	return out
}
func Lookup(id string) (Control, bool) {
	for _, c := range Catalog() {
		if c.ID == id {
			return c, true
		}
	}
	return Control{}, false
}
func ForSignal(signal string) []Control {
	var out []Control
	for _, c := range Catalog() {
		for _, s := range c.Signals {
			if s == signal {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

type Technology struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Evidence []string `json:"evidence"`
}
type Profile struct {
	Technologies   []Technology        `json:"technologies"`
	ManifestFlags  map[string]string   `json:"manifest_flags"`
	DeepLinks      []string            `json:"deep_links"`
	DebugArtifacts []string            `json:"debug_artifacts"`
	Signals        map[string][]string `json:"signals"`
	BytesInspected int64               `json:"bytes_inspected"`
	Truncated      bool                `json:"truncated"`
	Limitations    []string            `json:"limitations"`
}
