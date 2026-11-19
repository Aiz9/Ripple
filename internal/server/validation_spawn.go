package server

import (
	"fmt"
	"log"

	"github.com/Aiz9/ripple/internal/db"
)

// spawnValidationFor returns the worker callback that, when a worker reports a
// finding, creates an independent validation intent for it (Strix's
// discovery→validation split). A free worker in the pool claims that intent and
// reproduces the finding from scratch; if it cannot, it withdraws it. The worker
// side only calls this for findings filed by non-validation intents, so chains
// cannot form. Returns nil-safe behaviour via the auto_validate_findings setting,
// re-read per finding so the toggle takes effect without rebuilding the agent.
func (s *Server) spawnValidationFor(t *Task) func(findingID, findingNodeID int64, summary string) {
	return func(findingID, findingNodeID int64, summary string) {
		if !s.m.AutoValidateFindings() {
			return
		}
		desc := fmt.Sprintf(
			"Independently validate finding #%d (%s). Reproduce it FROM SCRATCH in a fresh session: do not trust the original evidence — re-trigger the vulnerability yourself and capture a working PoC (for API findings, the proving request/response plus its baseline/control). If you confirm it, record the reproduction as a fact. If re-testing shows it is not a real vulnerability (your own test setup, intended behaviour, or the control is enforced after all), call withdraw_finding. Record the outcome with record_test_coverage.",
			findingID, summary)
		audit := db.Activity{
			Worker:  "system",
			Kind:    "text",
			Summary: "Auto validation intent",
			Detail:  desc,
		}
		intentID, audit, err := t.Store.AddFindingFollowUpIntent(findingID, findingNodeID, desc, audit)
		if err != nil {
			log.Printf("[validation] task %s finding #%d: spawn failed: %v", t.ID, findingNodeID, err)
			return
		}
		// The audit row committed atomically with the intent; publish that exact row
		// (emitActivity would insert a duplicate). Then wake the pool to claim it.
		s.engine.Broadcaster().Publish(t.ID, audit)
		t.Notify()
		log.Printf("[validation] task %s spawned validation intent #%d for finding #%d", t.ID, intentID, findingNodeID)
	}
}
