package agent

import (
	"context"

	"github.com/Autumn-27/artex/internal/db"
)

// FindingRecorder is injected by the host; agents never synthesize or copy
// evidence bodies themselves. Its implementation owns the atomic write.
type FindingRecorder interface {
	Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error)
}

// Tool-use guidance is appended without replacing the user's editable prompt.
// It does not require capture or claim that unavailable traffic tools exist.
const findingTrafficGuidance = "\n\n**Finding traffic evidence (optional)**: when calling report_finding, use traffic_refs to bind real HTTP request/response IDs in reproduction order only after viewing them and confirming they support the finding. Domain and time filter candidates but do not establish association. For TCP/non-HTTP findings, missing capture, or no exact match, omit the field or pass []; keep command output, logs, or other verifiable evidence in evidence and preferably explain why traffic is unbound. Never guess IDs or repeat probes solely to collect traffic."

func (t *ToolSet) SetFindingRecorder(r FindingRecorder)   { t.findingRecorder = r }
func (w *Worker) SetFindingRecorder(r FindingRecorder)    { w.findingRecorder = r }
func (p *Planner) SetFindingRecorder(r FindingRecorder)   { p.findingRecorder = r }
func (m *MainAgent) SetFindingRecorder(r FindingRecorder) { m.findingRecorder = r }
