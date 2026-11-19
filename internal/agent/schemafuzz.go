package agent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Aiz9/ripple/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// Schema-driven robustness probe. Not generic payload fuzzing: it mutates the
// fields of a REAL captured request against their observed shape (type violation,
// null, removal, oversized) and replays each, flagging responses that reveal weak
// server-side input handling — chiefly a 5xx (the input reached an unhandled code
// path). Deterministic: the finding is the exact field+mutation that broke the
// server, reproducible from the captured request.

type mutation struct {
	Field string `json:"field"`
	Kind  string `json:"kind"`
	req   string // full tampered request, ready to send
}

// rawKind classifies a JSON raw value.
func rawKind(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "empty"
	}
	switch raw[0] {
	case '"':
		return "string"
	case '[':
		return "array"
	case '{':
		return "object"
	case 't', 'f':
		return "bool"
	case 'n':
		return "null"
	default:
		return "number"
	}
}

// typeFlip returns a value of a deliberately wrong type for the given kind.
func typeFlip(kind string) (string, string) {
	switch kind {
	case "number":
		return `"not_a_number"`, "number→string"
	case "string":
		return `123456789`, "string→number"
	case "bool":
		return `"maybe"`, "bool→string"
	case "array":
		return `"x"`, "array→string"
	case "object":
		return `0`, "object→number"
	default:
		return `"x"`, "any→string"
	}
}

// typeKind maps an inferred field type to typeFlip's kind vocabulary.
func typeKind(t string) string {
	switch t {
	case "integer", "number":
		return "number"
	case "boolean":
		return "bool"
	default:
		return t
	}
}

// requestMutations generates per-field robustness mutations of a request's body
// (JSON or form): a wrong-type value, null, removal, and an oversized value. Each
// mutation is a full tampered request, ready to send.
func requestMutations(rawRequest string) []mutation {
	format, fields := bodyFieldTypes(rawRequest)
	if len(fields) == 0 {
		return nil
	}
	var out []mutation
	for field, typ := range fields {
		if typ != "null" {
			flip, desc := typeFlip(typeKind(typ))
			if nr, ok := setBodyFieldRaw(rawRequest, field, flip); ok {
				out = append(out, mutation{Field: field, Kind: desc, req: nr})
			}
		}
		if nr, ok := setBodyFieldRaw(rawRequest, field, "null"); ok {
			out = append(out, mutation{Field: field, Kind: "null", req: nr})
		}
		if typ == "string" || format == "form" {
			if nr, ok := setBodyFieldString(rawRequest, field, strings.Repeat("A", 5000)); ok {
				out = append(out, mutation{Field: field, Kind: "oversized", req: nr})
			}
		}
		if nr, ok := removeBodyField(rawRequest, field); ok {
			out = append(out, mutation{Field: field, Kind: "removed", req: nr})
		}
	}
	return out
}

// isServerError reports an unhandled-input signal (5xx).
func isServerError(status int) bool { return status >= 500 && status < 600 }

func (t *ToolSet) mobileSchemaFuzz() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":       strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"history_index": intField("history index of a captured request with a JSON body to robustness-test"),
			"max_mutations": intField("cap on mutations to send (default 40)"),
		},
		"required":             []any{"history_index"},
		"additionalProperties": false,
	}
	return writeTool("mobile_schema_fuzz",
		"Schema-driven robustness probe for one captured request. Mutates each JSON body field against its observed type (wrong type, null, removal, oversized) and replays, flagging responses that reveal weak input handling — primarily a 5xx (input reached an unhandled path). Targeted to a real endpoint, not blind fuzzing; the finding names the exact field+mutation that broke the server. SANDBOX ONLY.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				MCPURL       string `json:"mcp_url"`
				HistoryIndex *int   `json:"history_index"`
				MaxMutations int    `json:"max_mutations"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if a.HistoryIndex == nil || *a.HistoryIndex < 0 {
				return actool.Errorf("history_index (>= 0) is required"), nil
			}
			if a.MaxMutations <= 0 {
				a.MaxMutations = 40
			}
			if a.MCPURL == "" {
				a.MCPURL = devicelab.BurpMCPURL()
			}
			c, err := devicelab.DialBurpMCP(ctx, a.MCPURL)
			if err != nil {
				return errf("connect Burp MCP: %v", err), nil
			}
			defer c.Close()
			ex, herr := c.ProxyHistory(ctx, *a.HistoryIndex, 1)
			if herr != nil {
				return errf("read history: %v", herr), nil
			}
			if len(ex) == 0 {
				return errf("no captured exchange at history_index %d", *a.HistoryIndex), nil
			}
			req := ex[0]
			recordCoverage(t.taskID, coverageKey(req), "schema-fuzz")
			if !hasMutableBody(req.Request) {
				return actool.Errorf("captured request has no JSON or form body to mutate"), nil
			}
			muts := requestMutations(req.Request)
			if len(muts) > a.MaxMutations {
				muts = muts[:a.MaxMutations]
			}
			port := 443
			if !req.TLS {
				port = 80
			}
			type res struct {
				Field  string `json:"field"`
				Kind   string `json:"kind"`
				Status int    `json:"status"`
				Error  bool   `json:"server_error"`
			}
			var results []res
			var errorsHit []string
			for _, mu := range muts {
				resp, e := c.SendRequest(ctx, req.Host, port, req.TLS, mu.req)
				if e != nil {
					continue
				}
				st := httpStatus(resp)
				se := isServerError(st)
				results = append(results, res{Field: mu.Field, Kind: mu.Kind, Status: st, Error: se})
				if se {
					errorsHit = append(errorsHit, mu.Field+" ("+mu.Kind+") → HTTP "+itoa(st))
				}
			}
			result := map[string]any{
				"endpoint":       req.Method + " " + req.Host + req.Path,
				"mutations_sent": len(results),
				"server_errors":  len(errorsHit),
				"results":        results,
				"note":           "a 5xx on a malformed field means the input reached an unhandled path (improper input validation / exceptional condition); a clean 4xx is correct rejection.",
			}
			if len(errorsHit) > 0 {
				fb := &findingBlock{
					VulnClass:        "Improper input validation / unhandled exception (server error on malformed input)",
					Name:             "Unhandled malformed input on " + req.Method + " " + req.Path,
					Severity:         "medium",
					Summary:          "Mutating captured request fields caused server errors (5xx), indicating input reaches unhandled code paths rather than being validated/rejected.",
					AffectedEndpoint: req.Host + req.Path,
					Method:           req.Method,
					Preconditions:    "A captured request with a JSON body against an authorized sandbox.",
					Reproduction: append([]string{"Replay " + req.Method + " " + req.Path + " with each malformed field below:"},
						errorsHit...),
					Expected:           "Malformed input is rejected with a 4xx and a safe error; no 5xx.",
					Actual:             "Server returned 5xx for: " + strings.Join(errorsHit, "; "),
					Impact:             "Weak input validation / exceptional-condition handling; may hide injection or denial-of-service surface and indicates missing server-side type/constraint checks.",
					Remediation:        "Validate and constrain every input server-side (type, range, length, presence) and return a controlled 4xx; never let malformed input reach an unhandled path.",
					VerificationStatus: "confirmed",
				}
				if id, ok := t.fileFinding(ctx, fb, t.endpointAssetID("https://"+req.Host+req.Path, req.Method)); ok {
					fb.FiledFindingID = id
				}
				result["finding"] = fb
			}
			out, _ := json.Marshal(result)
			return actool.Text(string(out)), nil
		})
}
