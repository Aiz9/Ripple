package agent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Aiz9/ripple/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// GraphQL probe. The single highest-signal, deterministic GraphQL check is whether
// schema introspection is enabled in production: it hands an attacker the full type
// system (every query, mutation and field), which greatly eases every other attack.
// Confirmed when the introspection query returns a __schema with types.

const introspectionBody = `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind } } }"}`

// looksGraphQL reports whether a request is a GraphQL request (path or JSON body
// carrying a query/mutation).
func looksGraphQL(rawRequest string) bool {
	nl := strings.IndexAny(rawRequest, "\r\n")
	line := rawRequest
	if nl >= 0 {
		line = rawRequest[:nl]
	}
	if strings.Contains(strings.ToLower(line), "graphql") {
		return true
	}
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(strings.TrimSpace(httpBody(rawRequest))), &m) == nil {
		_, hasQuery := m["query"]
		_, hasMutation := m["mutation"]
		return hasQuery || hasMutation
	}
	return false
}

// introspectionEnabled reports whether a response is a successful introspection
// result (schema returned).
func introspectionEnabled(status int, respBody string) bool {
	if status < 200 || status >= 300 {
		return false
	}
	var r struct {
		Data struct {
			Schema json.RawMessage `json:"__schema"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(respBody)), &r) != nil {
		return false
	}
	return len(r.Data.Schema) > 0 && strings.Contains(string(r.Data.Schema), "types")
}

func (t *ToolSet) mobileGraphQLProbe() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":       strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"history_index": intField("history index of a captured GraphQL request (POST with a JSON query body, or a /graphql endpoint)"),
		},
		"required":             []any{"history_index"},
		"additionalProperties": false,
	}
	return writeTool("mobile_graphql_probe",
		"GraphQL security probe. Replays a captured GraphQL request's endpoint with a schema-introspection query; if the server returns the schema, introspection is enabled in production — an information-disclosure finding that exposes the full type system (every query/mutation/field) to attackers. Preserves the request's auth headers. Confirmed only when the introspection schema is actually returned.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				MCPURL       string `json:"mcp_url"`
				HistoryIndex *int   `json:"history_index"`
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
			if !looksGraphQL(req.Request) {
				return actool.Errorf("captured request does not look like GraphQL (no query/mutation body, no graphql path)"), nil
			}
			recordCoverage(t.taskID, coverageKey(req), "graphql")
			port := 443
			if !req.TLS {
				port = 80
			}
			introReq := setRequestBody(req.Request, introspectionBody)
			resp, e := c.SendRequest(ctx, req.Host, port, req.TLS, introReq)
			if e != nil {
				return errf("introspection replay: %v", e), nil
			}
			enabled := introspectionEnabled(httpStatus(resp), httpBody(resp))
			result := map[string]any{
				"endpoint":              req.Method + " " + req.Host + req.Path,
				"introspection_enabled": enabled,
				"status":                httpStatus(resp),
				"note":                  "introspection enabled in production exposes the full schema to attackers.",
			}
			if enabled {
				fb := &findingBlock{
					VulnClass:        "GraphQL schema introspection enabled",
					Name:             "GraphQL introspection enabled on " + req.Method + " " + req.Path,
					Severity:         "medium",
					Summary:          "The GraphQL endpoint answers introspection queries, exposing its full type system (all queries, mutations and fields).",
					AffectedEndpoint: req.Host + req.Path,
					Method:           req.Method,
					Preconditions:    "A captured GraphQL request.",
					Reproduction: []string{
						"Send the standard introspection query to " + req.Method + " " + req.Path + ".",
						"Observe the server returns the __schema type system.",
					},
					Expected:           "Introspection is disabled in production; the server rejects introspection queries.",
					Actual:             "The server returned the full schema via introspection.",
					Impact:             "Attackers obtain the complete API surface (hidden queries/mutations, field names, types), accelerating authorization and injection attacks.",
					Remediation:        "Disable introspection in production; restrict it to trusted/dev environments; apply field-level authorization and query depth/complexity limits.",
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
