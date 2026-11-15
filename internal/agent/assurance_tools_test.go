package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/internal/db"
)

func callTool(t *testing.T, name string, ts *ToolSet, payload any) (string, bool) {
	t.Helper()
	raw, _ := json.Marshal(payload)
	for _, tool := range append(ts.PlannerTools(), ts.WorkerTools()...) {
		if tool.Name() == name {
			res, err := tool.Call(context.Background(), raw, nil)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			return res.Flatten(), res.IsError
		}
	}
	t.Fatalf("tool %s not found", name)
	return "", false
}

func TestAssuranceWorkflow(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	expID, err := d.CreateExploration("assurance", "goal")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)
	goal, _ := es.AddGoal(map[string]any{"text": "find authz issues"}, "human")
	fact, _ := es.AddNode(db.KindFact, map[string]any{"summary": "x"}, 0, "confirmed", "w", nil)
	ts := NewToolSet(es, "planner")

	// Unit of work: more than 3 skills is refused; vuln_class/component land in the payload.
	if out, isErr := callTool(t, "add_intent", ts, map[string]any{"summary": "s", "skills": []string{"a", "b", "c", "d"}}); !isErr {
		t.Fatalf("4 skills accepted: %s", out)
	}
	out, isErr := callTool(t, "add_intent", ts, map[string]any{"summary": "idor on accounts", "vuln_class": "idor", "component": "GET /accounts/{id}", "skills": []string{"api-recon"}})
	if isErr {
		t.Fatal(out)
	}
	intents, _ := es.ListByKind(db.KindIntent, 10)
	if len(intents) != 1 || !strings.Contains(string(intents[0].Payload), `"vuln_class": "idor"`) {
		t.Fatalf("intent payload: %s", intents[0].Payload)
	}
	if !strings.Contains(renderIntentTask(intents[0]), "load these skills with the Skill tool and follow them: api-recon") {
		t.Fatal("skills not rendered into worker task")
	}

	// Finish gate: a live intent blocks proving the last goal.
	if out, isErr := callTool(t, "prove_goal", ts, map[string]any{"goal_id": goal, "evidence_id": fact}); !isErr || !strings.Contains(out, "intents are still open") {
		t.Fatalf("live intent did not block: %s", out)
	}
	_ = es.SetIntentState(intents[0].ID, "done")

	// Coverage: negative outcome needs evidence; needs_follow_up blocks finishing.
	if out, isErr := callTool(t, "record_test_coverage", ts, map[string]any{"surface": "GET /accounts/{id}", "risk": "IDOR", "outcome": "ruled_out"}); !isErr {
		t.Fatalf("ruled_out without evidence accepted: %s", out)
	}
	callTool(t, "record_test_coverage", ts, map[string]any{"surface": "GET /accounts/{id}", "risk": "IDOR", "outcome": "needs_follow_up", "evidence": "second account missing"})
	if out, isErr := callTool(t, "prove_goal", ts, map[string]any{"goal_id": goal, "evidence_id": fact}); !isErr || !strings.Contains(out, "needs_follow_up") {
		t.Fatalf("open coverage did not block: %s", out)
	}
	if !strings.Contains(coverageBlock(es), "GET /accounts/{id} / idor") {
		t.Fatal("planner coverage block missing open row")
	}
	// Same surface+risk moves the existing row (risk is case-normalised).
	callTool(t, "record_test_coverage", ts, map[string]any{"surface": "GET /accounts/{id}", "risk": "idor", "outcome": "blocked", "evidence": "only one test account supplied"})
	if rows, _ := es.ListCoverage(""); len(rows) != 1 || rows[0].Outcome != "blocked" {
		t.Fatalf("coverage not upserted: %+v", rows)
	}

	// report_finding requires confidence + counterevidence and stores them in evidence.
	wts := NewToolSet(es, "worker")
	if out, isErr := callTool(t, "report_finding", wts, map[string]any{"vulnclass": "idor", "severity": "high", "summary": "s1"}); !isErr {
		t.Fatalf("finding without counterevidence accepted: %s", out)
	}
	for _, s := range []string{"idor on accounts", "missing step-up on transfer"} {
		out, isErr := callTool(t, "report_finding", wts, map[string]any{"vulnclass": s, "severity": "high", "summary": s, "evidence": "req/resp", "confidence": "high", "counterevidence": "checked own session"})
		if isErr {
			t.Fatal(out)
		}
	}
	findings, _ := es.ListByKind(db.KindFinding, 10)
	if len(findings) != 2 || !strings.Contains(string(findings[0].Payload), "Counterevidence") {
		t.Fatalf("findings: %d %s", len(findings), findings[0].Payload)
	}

	// Two confirmed findings → chain analysis required, then the task completes.
	if out, isErr := callTool(t, "prove_goal", ts, map[string]any{"goal_id": goal, "evidence_id": findings[0].ID}); !isErr || !strings.Contains(out, "chain_analysis") {
		t.Fatalf("missing chain analysis did not block: %s", out)
	}
	// Withdrawn findings cannot prove a goal.
	if out, isErr := callTool(t, "withdraw_finding", ts, map[string]any{"finding_node_id": findings[1].ID, "reason": "own session"}); isErr {
		t.Fatal(out)
	}
	if out, isErr := callTool(t, "prove_goal", ts, map[string]any{"goal_id": goal, "evidence_id": findings[1].ID, "chain_analysis": "x"}); !isErr {
		t.Fatalf("withdrawn finding proved a goal: %s", out)
	}
	if out, isErr := callTool(t, "prove_goal", ts, map[string]any{"goal_id": goal, "evidence_id": findings[0].ID}); isErr || !ts.GoalMet {
		t.Fatalf("prove_goal after reconciliation: %s", out) // one confirmed finding left → no chain analysis needed
	}

	// Threat model: sections enforced, amendments rendered.
	if out, isErr := callTool(t, "save_threat_model", ts, map[string]any{"content": "# Overview\nx"}); !isErr {
		t.Fatalf("incomplete threat model accepted: %s", out)
	}
	callTool(t, "save_threat_model", ts, map[string]any{"content": "## Overview\na\n## Trust boundaries\nb\n## Attack surface\nc\n## Severity calibration\nd"})
	callTool(t, "amend_threat_model", wts, map[string]any{"addendum": "OTP checked client-side only"})
	if b := threatModelBlock(es, "worker"); !strings.Contains(b, "Severity calibration") || !strings.Contains(b, "OTP checked client-side only") {
		t.Fatalf("threat model block: %s", b)
	}
}

func TestSpawnValidationGuard(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	expID, err := d.CreateExploration("spawnval", "goal")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	callReport := func(ts *ToolSet) (string, bool) {
		for _, tool := range ts.WorkerTools() {
			if tool.Name() == "report_finding" {
				res, err := tool.Call(context.Background(), []byte(`{"vulnclass":"idor","severity":"high","summary":"s","evidence":"e","confidence":"high","counterevidence":"c"}`), nil)
				if err != nil {
					t.Fatal(err)
				}
				return res.Flatten(), res.IsError
			}
		}
		t.Fatal("no report_finding")
		return "", false
	}

	// A finding filed on a normal intent spawns one validation.
	normal, _ := es.AddIntent(map[string]any{"summary": "idor"}, 5, nil, "planner")
	spawned := 0
	ts := NewToolSet(es, "worker")
	ts.SetFindingRecorder(nil)
	ts.SetOwnerNode(normal)
	ts.SetSpawnValidation(func(fid, nid int64, summary string) { spawned++ })
	if out, isErr := callReport(ts); isErr {
		t.Fatal(out)
	}
	if spawned != 1 {
		t.Fatalf("normal intent: want 1 validation spawn, got %d", spawned)
	}

	// A finding filed on a validation intent (payload carries source_finding_id, as
	// AddFindingFollowUpIntent sets it) must NOT spawn again — the recursion guard.
	valIntent, err := es.AddIntent(map[string]any{"summary": "validate", "source_finding_id": 999}, 10, nil, "human")
	if err != nil {
		t.Fatal(err)
	}
	spawned = 0
	vts := NewToolSet(es, "worker")
	vts.SetFindingRecorder(nil)
	vts.SetOwnerNode(valIntent)
	vts.SetSpawnValidation(func(fid, nid int64, summary string) { spawned++ })
	if out, isErr := callReport(vts); isErr {
		t.Fatal(out)
	}
	if spawned != 0 {
		t.Fatalf("validation intent: want 0 re-spawn, got %d", spawned)
	}
}
