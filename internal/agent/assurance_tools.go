package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Aiz9/ripple/internal/db"
	actool "github.com/Autumn-27/norma/tool"
)

// highRiskEndpointPattern flags money-movement / auth / cross-channel endpoints
// whose authorization must be exercised before a task may be declared done. A
// token-audience-confusion bug (task 774: a CONVERGENT/BPS token accepted on a
// legacy fund-transfer / QR-payment route) hides exactly on these, so leaving one
// unanchored to any fact must block finish rather than silently pass.
var highRiskEndpointPattern = regexp.MustCompile(`(?i)(payment|transfer|/pay\b|/qr|convergent|nqr|fund|/login|/token|thirdparty|third-party|account/link|/sso)`)

// Test-assurance tools: coverage ledger with closure states, shared threat model,
// and finding withdrawal. Bound to planner + worker.

// WorkerSkillNames, if set, lists the skill names visible to the worker agent so
// add_intent can validate per-intent skills and the planner can see what exists.
// Wired in server/assembly.go; nil = no validation and no list.
var WorkerSkillNames func() []string

// threatModelMaxChars bounds the threat model rendered into every prompt.
const threatModelMaxChars = 8000

func (t *ToolSet) recordTestCoverage() actool.CoreTool {
	return t.writeExpTool("record_test_coverage",
		"Record how one tested surface × risk closed, in the task's shared coverage ledger. Record EVERY surface you assess, including clean ones — a report that lists only findings cannot show what was reviewed. Calling again for the same surface+risk moves that row to its new outcome (use this when you resolve a row another agent left open).\n"+
			"Outcomes: reported (a finding was filed) | no_issue_found (tested, nothing found) | ruled_out (evidence MUST name the specific control, at a location, that runs on every attacker-reachable path) | not_applicable (evidence says why) | needs_follow_up (plausible but unproven: evidence says what is missing and what would prove it) | blocked (cannot be completed here: evidence names the concrete blocker, e.g. no second account, root unavailable).\n"+
			"Missing information is NOT proof of safety: no caller found, could not reach the endpoint, build failed → needs_follow_up or blocked, never ruled_out.",
		obj(map[string]any{
			"surface":   str("What was tested, specific enough to re-test: endpoint+method (POST /api/v1/transfer), component (exported activity com.x.DeepLinkActivity), storage location, or MASVS control id plus its target"),
			"risk":      str("Risk / vulnerability class tested on that surface, e.g. idor, sqli, auth-bypass, insecure-storage, ssl-pinning, business-logic:transfer-replay"),
			"outcome":   map[string]any{"type": "string", "enum": db.CoverageOutcomes},
			"evidence":  str("Why this outcome: request/response or command excerpt, the control that blocks it, or the blocker. Required for every outcome except reported/no_issue_found"),
			"intent_id": idp("Your intent ID (workers)"),
		}, "surface", "risk", "outcome"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Surface, Risk, Outcome, Evidence string
				IntentID                         json.RawMessage `json:"intent_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			// Impact-probe discipline (task 774): a money-movement surface must not be
			// closed as safe on an invalid measurement — a broken probe (post_balance=None),
			// a settlement-rail outage, or a transport error means "no effect observed"
			// proves nothing. Force needs_follow_up/blocked instead of a false all-clear.
			if (a.Outcome == "no_issue_found" || a.Outcome == "ruled_out") &&
				highRiskEndpointPattern.MatchString(a.Surface+" "+a.Risk) &&
				invalidMeasurement(a.Evidence) {
				return actool.Errorf("this evidence shows the measurement was invalid or blocked (outage / transport error / null balance read), so it cannot support a safety outcome on a money-movement surface. Re-measure with the side-effect channel confirmed live, or record needs_follow_up (what is missing) / blocked (the concrete blocker)."), nil
			}
			iid := pid(a.IntentID)
			if iid <= 0 && t.ownerNode > 0 {
				if n, _ := t.ts.GetNode(t.ownerNode); n != nil && n.Kind == db.KindIntent {
					iid = n.ID
				}
			}
			id, err := t.ts.RecordCoverage(a.Surface, a.Risk, a.Outcome, a.Evidence, iid, t.worker)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("coverage recorded: %d (%s / %s → %s)", id, a.Surface, a.Risk, a.Outcome)), nil
		})
}

func (t *ToolSet) listTestCoverage() actool.CoreTool {
	return t.readExpTool("list_test_coverage", "List the task's coverage ledger (surface × risk → outcome + evidence), optionally filtered to one outcome. Check it before testing to avoid redoing closed ground; the planner uses outcome=needs_follow_up to find owed work.",
		obj(map[string]any{"outcome": map[string]any{"type": "string", "enum": db.CoverageOutcomes, "description": "Optional filter"}}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Outcome string }
			_ = json.Unmarshal(in, &a)
			rows, err := t.ts.ListCoverage(a.Outcome)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(rows)
		})
}

func (t *ToolSet) saveThreatModel() actool.CoreTool {
	return t.writeExpTool("save_threat_model",
		"Save the task's shared threat model, which every planner round and worker launch reads. REPLACES the whole document and clears amendments, so use it to establish the baseline or to fold amendments in; to correct part of it use amend_threat_model. Markdown with these sections (all required): Overview (app, backend hosts, data handled), Trust boundaries (client vs backend: which checks the server enforces vs only the app; device/storage; third parties), Attack surface (APIs, roles/accounts, exported components, deep links, storage, WebViews), Severity calibration (what is critical HERE, e.g. moving funds, cross-account data, OTP bypass).",
		obj(map[string]any{"content": str("Full threat model (Markdown) with sections: Overview, Trust boundaries, Attack surface, Severity calibration")}, "content"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Content string }
			_ = json.Unmarshal(in, &a)
			if err := t.ts.SaveThreatModel(a.Content); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("threat model saved"), nil
		})
}

func (t *ToolSet) amendThreatModel() actool.CoreTool {
	return t.writeExpTool("amend_threat_model",
		"Append a correction to the shared threat model when your testing disproves or extends it: a boundary it calls trusted is attacker-reachable, a role/host/endpoint it never listed, a check it assumed server-side is client-only. Later agents inherit it; not optional when you found the model wrong.",
		obj(map[string]any{"addendum": str("The correction, with the evidence that supports it")}, "addendum"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Addendum string }
			_ = json.Unmarshal(in, &a)
			if err := t.ts.AmendThreatModel(t.worker, a.Addendum); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("threat model amended"), nil
		})
}

func (t *ToolSet) withdrawFinding() actool.CoreTool {
	return t.writeExpTool("withdraw_finding",
		"Withdraw a finding that re-testing proved is NOT a vulnerability (it only worked because of your own test setup, a mixed-up session, a misread response, or the control is in fact enforced). Marks it false_positive and removes it from goal evidence. Never leave a disproved finding on file or rewrite it into a 'retracted' note. A finding that is real but weaker than filed is not withdrawn.",
		obj(map[string]any{
			"finding_node_id": idp("Exploration node ID of the finding (finding_node_id / list_findings id)"),
			"reason":          str("Why it is not a vulnerability, with the evidence"),
		}, "finding_node_id", "reason"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				FindingNodeID json.RawMessage `json:"finding_node_id"`
				Reason        string
			}
			_ = json.Unmarshal(in, &a)
			nid := pid(a.FindingNodeID)
			if nid <= 0 || strings.TrimSpace(a.Reason) == "" {
				return actool.Errorf("finding_node_id and reason are required"), nil
			}
			if err := t.ts.WithdrawFinding(ctx, nid); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			// Keep the reason on the graph next to the dismissed node.
			if fid, err := t.recordOneFact(factItem{Summary: fmt.Sprintf("Finding %d withdrawn as false positive", nid), Detail: a.Reason, Confidence: "observed"}, t.ownerIntent()); err == nil && fid > 0 {
				_ = t.ts.Link(nid, db.RelDerivedFrom, fid)
			}
			if t.notify != nil {
				t.notify()
			}
			return actool.Text(fmt.Sprintf("finding %d withdrawn (false_positive)", nid)), nil
		})
}

// ownerIntent returns the worker's own intent id, 0 for planner-side tool sets.
func (t *ToolSet) ownerIntent() int64 {
	if t.ownerNode <= 0 {
		return 0
	}
	if n, _ := t.ts.GetNode(t.ownerNode); n != nil && n.Kind == db.KindIntent {
		return n.ID
	}
	return 0
}

// assuranceTools is the shared planner + worker set.
func (t *ToolSet) assuranceTools() []actool.CoreTool {
	return []actool.CoreTool{t.recordTestCoverage(), t.listTestCoverage(), t.saveThreatModel(), t.amendThreatModel(), t.withdrawFinding()}
}

// threatModelBlock renders the task's threat model for prompts, or a directive
// to create one when absent. role is "planner" or "worker".
func threatModelBlock(ts *db.ExplorationStore, role string) string {
	if ts == nil {
		return ""
	}
	m, err := ts.GetThreatModel()
	if err != nil {
		return ""
	}
	if m == nil {
		if role == "planner" {
			return "\n\n[Threat model]: none yet. Before dispatching vulnerability-testing intents, dispatch ONE threat-modelling intent (static manifest/code review + observed traffic) whose worker saves it with save_threat_model."
		}
		return "\n\n[Threat model]: none yet. If your intent is threat modelling, save it with save_threat_model; otherwise work from the evidence and note trust-boundary observations in your facts."
	}
	var b strings.Builder
	b.WriteString("\n\n[Shared threat model — work from it instead of re-deriving trust boundaries; amend_threat_model where your testing proves it wrong]:\n")
	b.WriteString(clipRunes(m.Content, threatModelMaxChars))
	for _, am := range m.Amendments {
		fmt.Fprintf(&b, "\n- Amendment (%s): %s", am.Agent, am.Text)
	}
	return b.String()
}

// coverageBlock renders the planner's view of the ledger: counts plus every row
// still owed (needs_follow_up) or blocked, which the planner must act on.
func coverageBlock(ts *db.ExplorationStore) string {
	if ts == nil {
		return ""
	}
	counts, err := ts.CoverageCounts()
	if err != nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Test coverage ledger]: ")
	if len(counts) == 0 {
		b.WriteString("empty — workers have not recorded any surface yet.")
	} else {
		c, _ := json.Marshal(counts)
		b.Write(c)
	}
	for _, outcome := range []string{"needs_follow_up", "blocked"} {
		rows, _ := ts.ListCoverage(outcome)
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s rows (", outcome)
		if outcome == "needs_follow_up" {
			b.WriteString("each must get a follow-up intent before the last goal can be proven")
		} else {
			b.WriteString("re-dispatch only if the blocker is now resolvable")
		}
		b.WriteString("):")
		for i, r := range rows {
			if i == 30 {
				fmt.Fprintf(&b, "\n… %d more (list_test_coverage outcome=%s)", len(rows)-30, outcome)
				break
			}
			fmt.Fprintf(&b, "\n- %s / %s: %s", r.Surface, r.Risk, clipRunes(r.Evidence, 200))
		}
	}
	if WorkerSkillNames != nil {
		if names := WorkerSkillNames(); len(names) > 0 {
			b.WriteString("\n\n[Worker skills available for add_intent.skills]: " + strings.Join(names, ", "))
		}
	}
	return b.String()
}

// finishGate is checked when prove_goal would mark the task's LAST open goal met:
// the strix-style finish preconditions. Returns "" when finishing is allowed.
func (t *ToolSet) finishGate(chainAnalysis string) string {
	var problems []string
	if live, _ := t.ts.HasActiveIntent(); live {
		problems = append(problems, "intents are still open or running: wait for them (end this round; you will be woken) or kill_work the ones no longer needed")
	}
	if rows, _ := t.ts.ListCoverage("needs_follow_up"); len(rows) > 0 {
		var s []string
		for i, r := range rows {
			if i == 10 {
				s = append(s, fmt.Sprintf("… %d more", len(rows)-10))
				break
			}
			s = append(s, r.Surface+" / "+r.Risk)
		}
		problems = append(problems, fmt.Sprintf("%d coverage rows are needs_follow_up (%s): dispatch intents that move each to its real outcome, or to blocked with the blocker stated", len(rows), strings.Join(s, "; ")))
	}
	if strings.TrimSpace(chainAnalysis) == "" {
		if n := t.confirmedFindingCount(); n >= 2 {
			problems = append(problems, fmt.Sprintf("chain_analysis is required with %d confirmed findings: state which combinations could chain into a higher-impact path, which were tested (filed as their own finding if they worked) and why the rest are unrelated", n))
		}
	}
	if untested := t.untestedHighRiskEndpoints(); len(untested) > 0 {
		problems = append(problems, fmt.Sprintf("%d high-risk endpoints are in scope with no fact/coverage anchoring them (%s): test each — mint a token from every login path (app, convergent/third-party, SSO, account-link) and replay across v1 and v2 — or record a coverage row with the reason it is not applicable. Enumeration is not coverage", len(untested), strings.Join(untested, "; ")))
	}
	if len(problems) == 0 {
		return ""
	}
	return "Cannot mark the last goal met yet — the task would finish with work outstanding:\n- " + strings.Join(problems, "\n- ")
}

// invalidMeasurementMarkers are phrases in coverage evidence that mean the test's
// observation channel failed, so a "no effect" reading is not evidence of safety.
var invalidMeasurementMarkers = []string{
	"outage", "connection reset", "connection timed out", "timed out", "timeout",
	"=none", "= none", "post_balance=none", "balance=none", "null balance",
	"500 ", "502", "503", "504", "service unavailable", "unavailable",
	"could not", "no response", "unreachable", "rail down", "settlement down",
	"probe bug", "script bug", "persistence bug", "read local out",
}

// invalidMeasurement reports whether evidence indicates a failed/blocked measurement.
func invalidMeasurement(evidence string) bool {
	e := strings.ToLower(evidence)
	for _, m := range invalidMeasurementMarkers {
		if strings.Contains(e, m) {
			return true
		}
	}
	return false
}

// untestedHighRiskEndpoints returns labels of in-scope endpoint assets that match
// highRiskEndpointPattern and are anchored to no fact (untested). Capped at 10.
// Returns nil when the asset store / task context is absent (tests, cross-task
// reads) so the gate never blocks spuriously.
func (t *ToolSet) untestedHighRiskEndpoints() []string {
	if t.as == nil || t.taskID <= 0 {
		return nil
	}
	assets, _, err := t.as.ListUntestedAssetsWithSources(t.taskID, "endpoint", 500, 0)
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range assets {
		if highRiskEndpointPattern.MatchString(a.Label) {
			out = append(out, a.Label)
			if len(out) == 10 {
				break
			}
		}
	}
	return out
}

func (t *ToolSet) confirmedFindingCount() int {
	f, _ := t.ts.ListByKind(db.KindFinding, 500)
	n := 0
	for _, x := range f {
		if x.State == "confirmed" {
			n++
		}
	}
	return n
}

// clipRunes truncates s to n runes, marking the cut.
func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// isLastOpenGoal reports whether goalID is the only goal still open.
func (t *ToolSet) isLastOpenGoal(goalID int64) bool {
	goals, err := t.ts.ListByKind(db.KindGoal, 1000)
	if err != nil {
		return false
	}
	for _, g := range goals {
		if g.ID != goalID && g.State == "open" {
			return false
		}
	}
	return true
}

// onValidationIntent reports whether this worker's own intent was spawned as a
// finding follow-up (payload carries source_finding_id). Such intents are the
// validation agents themselves, so a finding they file must not spawn another.
func (t *ToolSet) onValidationIntent() bool {
	if t.ownerNode <= 0 {
		return false
	}
	n, err := t.ts.GetNode(t.ownerNode)
	if err != nil || n == nil {
		return false
	}
	var p struct {
		SourceFindingID int64 `json:"source_finding_id"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return p.SourceFindingID > 0
}
