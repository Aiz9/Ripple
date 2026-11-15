package agent

import (
	"context"
	"encoding/json"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// Financial workflow as a state machine. A multi-step flow (initiate → verify →
// confirm) must be walked in order: a server that accepts a later step without its
// prerequisite has broken workflow enforcement (e.g. confirm a transfer that was
// never authorized). This models the flow as ordered states, groups captured
// requests by a correlation key (the object the flow acts on, e.g. a transaction
// id), and flags any ACCEPTED forward skip in the observed sequence — deterministic
// over captured traffic, so it confirms what the agent's skip attempts actually
// achieved rather than guessing.

type workflowStep struct {
	State   string `json:"state"`
	Method  string `json:"method,omitempty"`
	Pattern string `json:"pattern"` // glob over the normalized path
}

type workflowDef struct {
	States  []string       `json:"states"` // ordered: index = position in the flow
	Steps   []workflowStep `json:"steps"`
	KeyName string         `json:"correlation_field"` // param/path field grouping requests by object
}

var (
	workflowMu    sync.Mutex
	workflowStore = map[int64]workflowDef{} // taskID -> definition
)

func setWorkflow(taskID int64, d workflowDef) {
	workflowMu.Lock()
	defer workflowMu.Unlock()
	workflowStore[taskID] = d
}

func getWorkflow(taskID int64) (workflowDef, bool) {
	workflowMu.Lock()
	defer workflowMu.Unlock()
	d, ok := workflowStore[taskID]
	return d, ok
}

// stateIndex maps each state name to its position (0-based).
func stateIndex(states []string) map[string]int {
	m := make(map[string]int, len(states))
	for i, s := range states {
		m[s] = i
	}
	return m
}

// classifyStep returns the workflow state a (method, path) belongs to.
func classifyStep(steps []workflowStep, method, pathTemplate string) (string, bool) {
	for _, s := range steps {
		if s.Method != "" && !strings.EqualFold(s.Method, method) {
			continue
		}
		if ok, _ := path.Match(s.Pattern, pathTemplate); ok || s.Pattern == pathTemplate {
			return s.State, true
		}
	}
	return "", false
}

// fieldValue extracts the correlation key's value from a raw request (path segment
// match is not attempted; query and JSON body are checked — the common cases for a
// transaction/reference id).
func fieldValue(rawRequest, field string) string {
	if field == "" {
		return ""
	}
	// query
	nl := strings.IndexAny(rawRequest, "\r\n")
	line := rawRequest
	if nl >= 0 {
		line = rawRequest[:nl]
	}
	if f := strings.Fields(line); len(f) >= 2 {
		if i := strings.IndexByte(f[1], '?'); i >= 0 {
			if vals, err := url.ParseQuery(f[1][i+1:]); err == nil {
				if v := vals.Get(field); v != "" {
					return v
				}
			}
		}
	}
	// JSON body
	if b := strings.TrimSpace(httpBody(rawRequest)); strings.HasPrefix(b, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(b), &m) == nil {
			if v, ok := m[field]; ok {
				switch t := v.(type) {
				case string:
					return t
				case float64:
					return strings.TrimRight(strings.TrimRight(formatFloat(t), "0"), ".")
				}
			}
		}
	}
	return ""
}

func formatFloat(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

// seqViolations returns the forward-skip violations in an observed state sequence:
// a transition a→b where b is more than one state past a means the step(s) between
// were skipped. Backward/same transitions are not flagged (retries/re-reads).
func seqViolations(order map[string]int, seq []string) []string {
	var out []string
	for i := 1; i < len(seq); i++ {
		a, b := seq[i-1], seq[i]
		ai, aok := order[a]
		bi, bok := order[b]
		if !aok || !bok {
			continue
		}
		if bi > ai+1 {
			out = append(out, "reached '"+b+"' directly after '"+a+"' — skipped prerequisite step(s) in between")
		}
	}
	return out
}

func (t *ToolSet) mobileWorkflowSet() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"states":            strArr("ordered workflow state names, first to last (e.g. [\"initiate\",\"verify_otp\",\"confirm\"])"),
			"correlation_field": strField("query/body field whose value identifies the object the flow acts on (e.g. transaction_id), used to group requests"),
			"steps": map[string]any{
				"type":        "array",
				"description": "map each state to the request that performs it",
				"items": obj(map[string]any{
					"state":   strField("state name (must be one of states)"),
					"method":  strField("HTTP method; omit for any"),
					"pattern": strField("glob over the normalized path, e.g. /transfers/{id}/confirm"),
				}, "state", "pattern"),
			},
		},
		"required":             []any{"states", "steps", "correlation_field"},
		"additionalProperties": false,
	}
	return writeTool("mobile_workflow_set",
		"Define a financial workflow as an ordered state machine (e.g. initiate → verify_otp → confirm) so mobile_workflow_check can detect skipped-prerequisite / out-of-order acceptance. Provide the ordered state names, a correlation_field that identifies the object across steps, and a step matcher (state → method+path glob) for each state. Register this before driving skip attempts and running mobile_workflow_check.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var d workflowDef
			if err := json.Unmarshal(in, &d); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if len(d.States) < 2 {
				return actool.Errorf("at least two ordered states are required"), nil
			}
			if len(d.Steps) == 0 || strings.TrimSpace(d.KeyName) == "" {
				return actool.Errorf("steps and correlation_field are required"), nil
			}
			idx := stateIndex(d.States)
			for _, s := range d.Steps {
				if _, ok := idx[s.State]; !ok {
					return errf("step state %q is not in states", s.State), nil
				}
			}
			setWorkflow(t.taskID, d)
			out, _ := json.Marshal(map[string]any{"stored": true, "states": d.States, "steps": len(d.Steps), "correlation_field": d.KeyName})
			return actool.Text(string(out)), nil
		})
}

func (t *ToolSet) mobileWorkflowCheck() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url": strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"offset":  intField("history offset (default 0)"),
			"count":   intField("max exchanges to scan (default 500)"),
		},
		"additionalProperties": false,
	}
	return writeTool("mobile_workflow_check",
		"Check the registered workflow (mobile_workflow_set) against captured traffic. Groups requests by the correlation field, maps each to its state, and flags any ACCEPTED forward skip (a later step reached without its prerequisite) per object — a broken-workflow / invalid-state-transition finding. Deterministic: it confirms what the server actually accepted out of order. Drive skip attempts first (replay a later step without doing the earlier one) so there is out-of-order traffic to evaluate.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			d, ok := getWorkflow(t.taskID)
			if !ok {
				return actool.Errorf("no workflow registered; define it with mobile_workflow_set first"), nil
			}
			var a struct {
				MCPURL string `json:"mcp_url"`
				Offset int    `json:"offset"`
				Count  int    `json:"count"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if a.Count <= 0 {
				a.Count = 500
			}
			if a.MCPURL == "" {
				a.MCPURL = devicelab.BurpMCPURL()
			}
			c, err := devicelab.DialBurpMCP(ctx, a.MCPURL)
			if err != nil {
				return errf("connect Burp MCP: %v", err), nil
			}
			defer c.Close()
			hist, herr := c.ProxyHistory(ctx, a.Offset, a.Count)
			if herr != nil {
				return errf("read history: %v", herr), nil
			}
			order := stateIndex(d.States)

			// Group accepted step-requests by correlation key, preserving order.
			type ev struct {
				state  string
				method string
				path   string
			}
			groups := map[string][]ev{}
			var keyOrder []string
			for _, exch := range hist {
				method, canon, ok := exchangeEndpoint(exch)
				if !ok {
					continue
				}
				p := pathOf(canon)
				state, ok := classifyStep(d.Steps, method, p)
				if !ok {
					continue
				}
				if classifyTxn(httpStatus(exch.Response), httpBody(exch.Response)) != txnAccepted {
					continue // only accepted steps count toward an enforcement failure
				}
				key := fieldValue(exch.Request, d.KeyName)
				if key == "" {
					continue
				}
				if _, seen := groups[key]; !seen {
					keyOrder = append(keyOrder, key)
				}
				groups[key] = append(groups[key], ev{state, method, p})
			}

			type objResult struct {
				Key        string   `json:"object"`
				Sequence   []string `json:"sequence"`
				Violations []string `json:"violations,omitempty"`
			}
			var results []objResult
			var allViolations []string
			for _, key := range keyOrder {
				seq := make([]string, 0, len(groups[key]))
				for _, e := range groups[key] {
					seq = append(seq, e.state)
				}
				v := seqViolations(order, seq)
				results = append(results, objResult{Key: key, Sequence: seq, Violations: v})
				for _, vi := range v {
					allViolations = append(allViolations, "object "+key+": "+vi)
				}
			}
			sort.Slice(results, func(i, j int) bool { return results[i].Key < results[j].Key })

			result := map[string]any{
				"objects_tracked": len(results),
				"results":         results,
				"violations":      allViolations,
				"note":            "a violation means the server accepted a later workflow step without its prerequisite for that object (broken state-transition enforcement).",
			}
			if len(allViolations) > 0 {
				fb := &findingBlock{
					VulnClass:     "Business Logic — broken workflow / invalid state transition",
					Name:          "Workflow step order not enforced",
					Severity:      "high",
					Summary:       "The server accepted a later workflow step without its prerequisite, so a multi-step flow can be completed out of order.",
					Preconditions: "A declared workflow (ordered states) and captured traffic including an out-of-order attempt.",
					Reproduction: append([]string{"Define the flow states/steps; drive a later step without performing its prerequisite:"},
						allViolations...),
					Expected:           "The server rejects a step whose prerequisite state was not reached for that object.",
					Actual:             strings.Join(allViolations, "; "),
					Impact:             "Authorization/verification steps (e.g. OTP, approval, funding checks) can be bypassed, enabling unauthorized or unverified transactions.",
					Remediation:        "Enforce the workflow state machine server-side: persist each object's state and reject any transition that is not the permitted next step.",
					VerificationStatus: "confirmed",
				}
				if id, ok := t.fileFinding(ctx, fb, nil); ok {
					fb.FiledFindingID = id
				}
				result["finding"] = fb
			}
			out, _ := json.Marshal(result)
			return actool.Text(string(out)), nil
		})
}
