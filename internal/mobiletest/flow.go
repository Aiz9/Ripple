package mobiletest

import (
	"sort"
	"strconv"
	"strings"
)

// Phase is one ordered stage of the mobile assessment flow: a catalog section
// and the procedures it contains, in execution order. It is the coverage
// backbone the APK agent pipeline marches through (goals -> planner -> worker);
// membership is not a claim of automated execution.
type Phase struct {
	Index      int       `json:"index"`   // leading section number (1..N)
	Section    string    `json:"section"` // full section label, e.g. "05 Network and backend API security"
	Name       string    `json:"name"`    // section label without the numeric prefix
	Controls   []Control `json:"controls"`
	Objectives []string  `json:"objectives"` // distinct objectives covered (sorted)
	Requires   []string  `json:"requires"`   // distinct prerequisites across the phase (sorted)
	Signals    []string  `json:"signals"`    // distinct signals the phase's procedures are gated on (sorted)
}

// sectionIndex parses the leading "NN " number of a section label; 0 if absent.
func sectionIndex(section string) int {
	if fields := strings.Fields(section); len(fields) > 0 {
		if n, err := strconv.Atoi(fields[0]); err == nil {
			return n
		}
	}
	return 0
}

// sectionName is the section label without its leading numeric prefix.
func sectionName(section string) string {
	if fields := strings.Fields(section); len(fields) > 0 {
		if _, err := strconv.Atoi(fields[0]); err == nil {
			return strings.Join(fields[1:], " ")
		}
	}
	return section
}

// Flow returns the catalog grouped into phases ordered by section number — the
// defined methodology an APK assessment works through. Procedures keep their
// catalog order within a phase. Catalog membership is not a claim of automated
// execution or success.
func Flow() []Phase {
	bySection := map[string][]Control{}
	var order []string
	for _, c := range Catalog() {
		if _, seen := bySection[c.Section]; !seen {
			order = append(order, c.Section)
		}
		bySection[c.Section] = append(bySection[c.Section], c)
	}
	sort.SliceStable(order, func(i, j int) bool { return sectionIndex(order[i]) < sectionIndex(order[j]) })
	phases := make([]Phase, 0, len(order))
	for _, section := range order {
		controls := bySection[section]
		phases = append(phases, Phase{
			Index:      sectionIndex(section),
			Section:    section,
			Name:       sectionName(section),
			Controls:   controls,
			Objectives: distinctField(controls, func(c Control) []string { return []string{c.Objective} }),
			Requires:   distinctField(controls, func(c Control) []string { return c.Requires }),
			Signals:    distinctField(controls, func(c Control) []string { return c.Signals }),
		})
	}
	return phases
}

func distinctField(controls []Control, get func(Control) []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range controls {
		for _, v := range get(c) {
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
