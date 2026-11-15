package agent

import (
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/artex/internal/db"
	actool "github.com/Autumn-27/norma/tool"
)

const findingIDGuidance = "\n\n**Finding ID convention**: finding_id identifies the independent finding record; finding_node_id identifies the exploration node. The id from list_findings / list_task_findings / node_detail / get_task_node_detail remains a node ID; read finding_id from the same response for the independent ID. get_finding_traffic / bind_finding_traffic use the independent finding_id. Legacy update_finding_report still takes finding_node_id in its finding_id parameter. Do not use report_finding's first-line number for evidence tools or guess other IDs after an ID error."

// The server supplies the persisted setting. A missing setting/host is off.
// Consulted at assembly and again on writes so an already-running session
// cannot keep binding after the user switches the feature off.
var FindingTrafficBindingEnabled func() bool

func findingTrafficBindingEnabled() bool {
	return FindingTrafficBindingEnabled != nil && FindingTrafficBindingEnabled()
}

// Applied after ToolResolve: user descriptions and prompts remain intact, while
// all actual reporters (including Planner and custom chat agents) see the same
// API contract. Disabled/unbound tools are never reintroduced here.
func findingWorkflowTools(agentKey string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if !findingTrafficBindingEnabled() {
		out := make([]actool.CoreTool, 0, len(tools))
		for _, tool := range tools {
			if tool.Name() == "bind_finding_traffic" {
				continue
			}
			if agentKey == "reporter" && (tool.Name() == "traffic_search" || tool.Name() == "traffic_get" || tool.Name() == "traffic_blob") {
				continue
			}
			switch tool.Name() {
			case "report_finding", "add_hint", "add_task_hint":
				// Work on a copy: toggling back on must restore the original schema.
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				if json.Unmarshal(raw, &schema) == nil {
					stripTrafficParameters(schema)
					tool = DecorateTool(tool, tool.Description(), schema)
				}
			}
			out = append(out, tool)
		}
		return out, ""
	}
	out := append([]actool.CoreTool(nil), tools...)
	has := map[string]bool{}
	for i, tool := range out {
		has[tool.Name()] = true
		note := ""
		switch tool.Name() {
		case "report_finding":
			note = "\nBy default, the report agent verifies and binds traffic before writing the report. Preserve validation commands, key output, existing real traffic IDs, and their purpose in evidence so the reporter can verify against execution records; no extra packet lookup is required just for binding. Explicit immediate binding remains supported: traffic_refs supplies verified references; evidence_hint_id reads structured references from the specified hint in this task. Any invalid reference fails the entire submission. TCP/no-packet findings need neither optional parameter. The returned finding_id and finding_node_id identify the independent record and exploration node respectively."
		case "add_hint", "add_task_hint":
			note = "\nWhen handing off a confirmed finding, preserve verified traffic IDs, roles, explanations, and order in the corresponding hint's traffic_refs (top-level for one hint, per hints element for batches), and describe the specific finding it proves in text. Do not hand off only prose and discard existing traffic references. Unverified candidates must not be passed as evidence."
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "\n\n**Traffic evidence handoff (optional)**: default automatic binding is done by the report agent after the finding is saved and before its report is written. The submitter should preserve validation commands, key output, real traffic IDs, and their purpose in evidence, with intent_id in task context for traceability. No extra packet lookup is required just for binding. Auto / Planner submissions must retain the executor's existing references. add_hint / add_task_hint support traffic_refs handoff; explicit immediate binding through report_finding traffic_refs / evidence_hint_id remains compatible. Register TCP/no-packet findings normally; never guess IDs or repeat probes solely to collect packets."
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "\nWithout task context, a platform conversation must not call report_finding directly. Hand off through add_task_hint to the existing corresponding task, let its agent register the finding, and verify with list_task_findings."
		}
		if has["prove_goal"] || has["goal_met"] {
			guidance += "\nBefore declaring goals complete, finish reporting/handing off evidence already obtained in this run. Do not end the task or cancel Workers merely because a text finding was registered while evidence handoff is unfinished. Missing packets do not require waiting or forced capture."
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "\n\n**Automatic traffic association before reporting (enabled)**: verify and bind traffic for the finding that triggered this run, then write its report. Obtain explicit finding_id and finding_node_id from report_finding JSON or get_task_node_detail / list_task_findings. Read the finding, its intent execution trace, and existing evidence list; prefer real IDs handed off by the submitter. For HTTP verification with available traffic tools, filter candidates using traffic_search and verify each request/response with traffic_get. Domain and time only filter candidates and do not prove ownership. Bind confirmed evidence in reproduction order with bind_finding_traffic(finding_id, traffic_refs), choosing baseline / proof / verification / supporting and explaining its role. Operate only on this finding; do not recreate it or probe the target again. After binding, call get_finding_traffic again for the latest version, read the required bodies, and pass the version actually read as evidence_version to update_finding_report (whose finding_id parameter still takes finding_node_id). Do not append duplicate existing bindings. For TCP, missing capture, unavailable tools, or no exact match, skip automatic binding and write the report from text/command evidence with the reason. Never guess traffic to fill gaps. Do not claim a failed binding succeeded; retain existing evidence and explain the missing binding in the report."
	}
	if guidance != "" || has["get_finding_traffic"] || has["update_finding_report"] {
		guidance += findingIDGuidance
	}
	return out, guidance
}

func stripTrafficParameters(schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	delete(props, "traffic_refs")
	delete(props, "evidence_hint_id")
	if required, ok := schema["required"].([]any); ok {
		kept := required[:0]
		for _, key := range required {
			if key != "traffic_refs" && key != "evidence_hint_id" {
				kept = append(kept, key)
			}
		}
		schema["required"] = kept
	}
	if hints, ok := props["hints"].(map[string]any); ok {
		if items, ok := hints["items"].(map[string]any); ok {
			stripTrafficParameters(items)
		}
	}
}

// HintTrafficSchema is shared by the task-local and cross-task hint tools.
func HintTrafficSchema() map[string]any {
	return map[string]any{"type": "array", "description": "Optional verified traffic references supporting the specific finding in this hint, in order; report_finding can carry them using evidence_hint_id after handoff.", "items": obj(map[string]any{"traffic_id": str("Real traffic ID"), "role": str("baseline / proof / verification / supporting"), "note": str("Conclusion supported by this traffic")}, "traffic_id")}
}

func (t *ToolSet) findingRefsFromHint(hintID int64, explicit []db.TrafficRef) ([]db.TrafficRef, error) {
	if hintID <= 0 {
		return db.NormalizeTrafficRefs(explicit)
	}
	n, err := t.ts.GetNode(hintID) // local store only: inherited hints cannot supply evidence
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != db.KindHint {
		return nil, fmt.Errorf("evidence_hint_id=%d must identify a hint in this task (inherited hints cannot be bound directly)", hintID)
	}
	var payload struct {
		Refs []db.TrafficRef `json:"traffic_refs"`
	}
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		return nil, err
	}
	return db.NormalizeTrafficRefs(append(append([]db.TrafficRef{}, explicit...), payload.Refs...))
}
