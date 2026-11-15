package agent

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// Mass-assignment / auto-binding testing. A server that binds request fields
// straight onto its model lets a client set attributes it never should — role,
// verification, balance, ownership. This injects privileged fields the captured
// request did NOT contain, replays, and confirms ONLY when the response shows the
// injected value was actually applied (reflected back): a 2xx alone is not proof,
// because the field may be silently ignored.

// sensitiveFields maps a privilege-bearing field name to the raw JSON value to try
// setting it to. Names are matched case-insensitively against the object.
var sensitiveFields = map[string]string{
	"role":           `"admin"`,
	"roles":          `["admin"]`,
	"is_admin":       `true`,
	"isAdmin":        `true`,
	"admin":          `true`,
	"is_staff":       `true`,
	"superuser":      `true`,
	"is_superuser":   `true`,
	"verified":       `true`,
	"is_verified":    `true`,
	"email_verified": `true`,
	"approved":       `true`,
	"premium":        `true`,
	"account_type":   `"premium"`,
	"status":         `"approved"`,
	"balance":        `999999`,
	"credit":         `999999`,
	"permissions":    `["*"]`,
}

// addOrSetJSONField sets a top-level field in a JSON object body, adding it when
// absent (unlike setJSONField, which only replaces existing fields).
func addOrSetJSONField(body, field, rawValue string) (string, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &m) != nil {
		return "", false
	}
	if m == nil {
		m = map[string]json.RawMessage{}
	}
	m[field] = json.RawMessage(rawValue)
	out, err := json.Marshal(m)
	if err != nil {
		return "", false
	}
	return string(out), true
}

// bodyHasField reports whether a JSON object body already contains the field
// (case-insensitive), so it is not counted as an injection.
func bodyHasField(body, field string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &m) != nil {
		return false
	}
	for k := range m {
		if strings.EqualFold(k, field) {
			return true
		}
	}
	return false
}

func normalizeJSONValue(raw string) string {
	var v any
	if json.Unmarshal([]byte(raw), &v) != nil {
		return strings.TrimSpace(raw)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// reflectsInjected reports whether the response body contains the field (anywhere,
// case-insensitive key match) set to the injected value — i.e. the server applied
// it. Value comparison is JSON-normalized so true == true, "admin" == "admin".
func reflectsInjected(responseBody, field, injectedRaw string) bool {
	var v any
	if json.Unmarshal([]byte(strings.TrimSpace(responseBody)), &v) != nil {
		return false
	}
	want := normalizeJSONValue(injectedRaw)
	found := false
	var walk func(key string, val any)
	walk = func(key string, val any) {
		if found {
			return
		}
		switch t := val.(type) {
		case map[string]any:
			for k, vv := range t {
				if strings.EqualFold(k, field) {
					if b, err := json.Marshal(vv); err == nil && string(b) == want {
						found = true
						return
					}
				}
				walk(k, vv)
			}
		case []any:
			for _, vv := range t {
				walk(key, vv)
			}
		}
	}
	walk("", v)
	return found
}

func (t *ToolSet) mobileMassAssignment() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":       strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"history_index": intField("history index of a captured create/update request (POST/PUT/PATCH with a JSON body) whose response echoes the object"),
			"extra_fields": map[string]any{
				"type":                 "object",
				"description":          "additional field→raw-JSON-value injections to try (merged with the built-in privilege fields), e.g. {\"tenant_id\":\"\\\"victim\\\"\"}",
				"additionalProperties": map[string]any{"type": "string"},
			},
		},
		"required":             []any{"history_index"},
		"additionalProperties": false,
	}
	return writeTool("mobile_mass_assignment",
		"Mass-assignment / auto-binding tester. Injects privilege-bearing fields the captured request did NOT include (role, is_admin, verified, balance, status, …; extend via extra_fields), replays, and confirms a finding ONLY when the response shows the injected value was applied (reflected) — a 2xx alone is not proof. Use on create/update endpoints whose response echoes the object. SANDBOX ONLY.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				MCPURL       string            `json:"mcp_url"`
				HistoryIndex *int              `json:"history_index"`
				ExtraFields  map[string]string `json:"extra_fields"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if a.HistoryIndex == nil || *a.HistoryIndex < 0 {
				return actool.Errorf("history_index (>= 0) is required"), nil
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
			body := httpBody(req.Request)
			if strings.TrimSpace(body) == "" || !strings.HasPrefix(strings.TrimSpace(body), "{") {
				return actool.Errorf("captured request has no JSON object body to extend"), nil
			}
			port := 443
			if !req.TLS {
				port = 80
			}
			// Build the injection set: built-ins + operator extras, skipping fields
			// already present in the request.
			inject := map[string]string{}
			for f, v := range sensitiveFields {
				inject[f] = v
			}
			for f, v := range a.ExtraFields {
				if strings.TrimSpace(f) != "" {
					inject[f] = v
				}
			}
			fields := make([]string, 0, len(inject))
			for f := range inject {
				if !bodyHasField(body, f) {
					fields = append(fields, f)
				}
			}
			sort.Strings(fields)

			type res struct {
				Field   string `json:"field"`
				Status  int    `json:"status"`
				Applied bool   `json:"applied"`
			}
			var results []res
			var applied []string
			for _, f := range fields {
				nb, ok := addOrSetJSONField(body, f, inject[f])
				if !ok {
					continue
				}
				resp, e := c.SendRequest(ctx, req.Host, port, req.TLS, setRequestBody(req.Request, nb))
				if e != nil {
					continue
				}
				st := httpStatus(resp)
				ap := (st >= 200 && st < 300) && reflectsInjected(httpBody(resp), f, inject[f])
				results = append(results, res{Field: f, Status: st, Applied: ap})
				if ap {
					applied = append(applied, f+"="+inject[f])
				}
			}

			result := map[string]any{
				"endpoint":        req.Method + " " + req.Host + req.Path,
				"fields_injected": len(results),
				"applied":         applied,
				"results":         results,
				"note":            "a field is a finding only when the response shows the injected privileged value was applied; a 2xx without reflection is not proof.",
			}
			if len(applied) > 0 {
				fb := &findingBlock{
					VulnClass:        "Mass Assignment (unsafe object binding)",
					Name:             "Mass assignment on " + req.Method + " " + req.Path,
					Severity:         "high",
					Summary:          "The server bound client-supplied privileged fields onto the object; injected values were accepted and reflected in the response.",
					AffectedEndpoint: req.Host + req.Path,
					Method:           req.Method,
					Preconditions:    "A captured create/update request with a JSON body whose response echoes the object (authorized sandbox).",
					Reproduction: append([]string{"Replay " + req.Method + " " + req.Path + " adding the field(s) below (absent from the legitimate request); observe them applied in the response:"},
						applied...),
					Expected:           "The server ignores or rejects fields not permitted on the object (allow-list binding).",
					Actual:             "Injected privileged fields applied: " + strings.Join(applied, ", "),
					Impact:             "Privilege escalation / integrity violation — a client can set role, verification, balance or ownership it must not control.",
					Remediation:        "Bind only an explicit allow-list of client-settable fields server-side; never mass-assign request bodies onto models; set privileged attributes server-side only.",
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
