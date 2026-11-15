package db

import (
	"database/sql"
	"regexp"
	"strings"
)

// Duplicate-finding suppression for the agent reporting path.
//
// A single APK/web task runs many MASVS-driven intents in parallel and over
// time; workers routinely rediscover the SAME underlying issue under different
// MASVS domains or with different wording (e.g. the same forgot-password
// account-enumeration endpoint reported as both an "AUTH" finding and an "API"
// finding). That produced long runs of near-identical finding rows.
//
// When report_finding sets RecordFindingInput.Dedup, RecordFindingTx compares a
// new finding against the ones already recorded for the SAME task. A strong
// match enriches the existing row (binds any new traffic, raises severity to the
// max) and returns it instead of inserting a duplicate. The heuristic is
// deliberately conservative: same artifact + different vulnerability (e.g. a
// leaked credential vs. a missing-integrity issue on the same config URL) must
// stay as two findings, so an anchor overlap alone is never enough — the titles
// or full texts must also be similar.

var (
	reFindingPath = regexp.MustCompile(`/[a-z0-9][a-z0-9/_.\-]{4,}`)
	reFindingHost = regexp.MustCompile(`[a-z0-9][a-z0-9\-]*\.[a-z0-9\-]+\.[a-z]{2,}`)
	reFindingCWE  = regexp.MustCompile(`cwe[\s\-]?\d+`)
	reFindingHex  = regexp.MustCompile(`0x[0-9a-f]{3,}`)
	reFindingWord = regexp.MustCompile(`[a-z0-9]{3,}`)
	reNonDigit    = regexp.MustCompile(`\D+`)
)

// Generic, high-frequency words that carry no distinguishing signal for these
// findings; dropping them keeps the title Jaccard from being inflated (or
// deflated) by boilerplate shared across almost every MASVS finding.
var findingStopwords = map[string]bool{
	"the": true, "and": true, "for": true, "via": true, "with": true, "not": true,
	"are": true, "from": true, "this": true, "that": true, "app": true, "android": true,
	"apk": true, "masvs": true, "finding": true, "use": true, "used": true, "using": true,
	"all": true, "any": true, "its": true, "per": true, "into": true, "over": true,
	"has": true, "was": true, "but": true, "can": true, "out": true, "which": true,
}

func findingTokenSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range reFindingWord.FindAllString(s, -1) {
		if !findingStopwords[w] {
			out[w] = true
		}
	}
	return out
}

func findingJaccard(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if b[k] {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

type findingSig struct {
	nameTokens map[string]bool
	textTokens map[string]bool
	anchors    []string // normalized paths/hosts/CWE/offsets
}

func buildFindingSig(name, summary string) findingSig {
	lname := strings.ToLower(name)
	ltext := strings.ToLower(name + " " + summary)
	sig := findingSig{
		nameTokens: findingTokenSet(lname),
		textTokens: findingTokenSet(ltext),
	}
	seen := map[string]bool{}
	add := func(a string) {
		if a != "" && !seen[a] {
			seen[a] = true
			sig.anchors = append(sig.anchors, a)
		}
	}
	for _, m := range reFindingCWE.FindAllString(ltext, -1) {
		add("cwe-" + reNonDigit.ReplaceAllString(m, ""))
	}
	for _, m := range reFindingHost.FindAllString(ltext, -1) {
		add("h:" + m)
	}
	for _, m := range reFindingPath.FindAllString(ltext, -1) {
		add("p:" + m)
	}
	for _, m := range reFindingHex.FindAllString(ltext, -1) {
		add("x:" + m)
	}
	return sig
}

// findingAnchorOverlap counts shared salient anchors. Endpoint paths match by
// containment (e.g. "/v2/forgot/password/username/validation" inside
// "/webbackend/v2/forgot/password/username/validation"); everything else by
// equality.
func findingAnchorOverlap(a, b findingSig) int {
	n := 0
	for _, x := range a.anchors {
		for _, y := range b.anchors {
			if x == y {
				n++
				break
			}
			if strings.HasPrefix(x, "p:") && strings.HasPrefix(y, "p:") {
				px, py := x[2:], y[2:]
				if len(px) >= 8 && len(py) >= 8 && (strings.Contains(px, py) || strings.Contains(py, px)) {
					n++
					break
				}
			}
		}
	}
	return n
}

// findingsDuplicate reports whether finding A should be folded into finding B
// (same task). Conservative by design — see the package note.
func findingsDuplicate(aName, aSummary, aClass, bName, bSummary, bClass string) bool {
	sa := buildFindingSig(aName, aSummary)
	sb := buildFindingSig(bName, bSummary)
	nameJ := findingJaccard(sa.nameTokens, sb.nameTokens)
	textJ := findingJaccard(sa.textTokens, sb.textTokens)
	anchors := findingAnchorOverlap(sa, sb)
	classEq := strings.TrimSpace(aClass) != "" && strings.EqualFold(strings.TrimSpace(aClass), strings.TrimSpace(bClass))

	switch {
	case nameJ >= 0.6: // near-identical titles
		return true
	case classEq && nameJ >= 0.4: // same class, clearly overlapping titles
		return true
	case anchors >= 1 && (nameJ >= 0.2 || textJ >= 0.45): // same artifact + similar description
		return true
	case classEq && textJ >= 0.6: // same class, overwhelmingly similar text
		return true
	}
	return false
}

func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium", "moderate":
		return 3
	case "low":
		return 2
	case "info", "informational", "none":
		return 1
	}
	return 0
}

// findExistingDuplicateFindingTx returns an already-recorded finding for the
// same task that the incoming finding duplicates, or nil. Runs under the task
// evidence lock held by RecordFindingTx, so it is race-safe against concurrent
// reporters in the same task.
func findExistingDuplicateFindingTx(tx *sql.Tx, in RecordFindingInput) (*RecordedFinding, error) {
	rows, err := tx.Query(`SELECT id,node_id,vulnclass,name,summary FROM findings WHERE task_id=$1 ORDER BY id`, in.TaskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type cand struct {
		id, node             int64
		class, name, summary string
	}
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.id, &c.node, &c.class, &c.name, &c.summary); err != nil {
			return nil, err
		}
		cands = append(cands, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, c := range cands {
		if findingsDuplicate(in.Name, in.Summary, in.VulnClass, c.name, c.summary, c.class) {
			return &RecordedFinding{FindingID: c.id, NodeID: c.node, Deduped: true}, nil
		}
	}
	return nil, nil
}

// raiseFindingSeverityTx bumps an existing finding's severity up to sev when the
// duplicate reports it as more severe, so folding never silently downgrades.
func raiseFindingSeverityTx(tx *sql.Tx, findingID int64, sev string) error {
	r := severityRank(sev)
	if r == 0 {
		return nil
	}
	var cur string
	if err := tx.QueryRow(`SELECT severity FROM findings WHERE id=$1`, findingID).Scan(&cur); err != nil {
		return err
	}
	if severityRank(cur) >= r {
		return nil
	}
	_, err := tx.Exec(`UPDATE findings SET severity=$1 WHERE id=$2`, sev, findingID)
	return err
}
