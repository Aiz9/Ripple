package agent

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Aiz9/ripple/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// Enriched API model derived from traffic: parameter and response schema TYPES,
// API version, and a numeric discovery confidence per endpoint. This layers on top
// of the flat inventory (names only) without changing it, so the agent can reason
// about shapes and trust, not just paths.

// inferJSONType classifies a raw JSON value.
func inferJSONType(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "null"
	}
	switch raw[0] {
	case '"':
		return "string"
	case '[':
		return "array"
	case '{':
		return "object"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		if strings.ContainsAny(raw, ".eE") {
			if _, err := strconv.ParseFloat(raw, 64); err == nil {
				return "number"
			}
		}
		if _, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return "integer"
		}
		if _, err := strconv.ParseFloat(raw, 64); err == nil {
			return "number"
		}
		return "string"
	}
}

// inferStringType classifies a bare (unquoted) string value, as found in query
// parameters where everything arrives as text.
func inferStringType(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "false":
		return "boolean"
	case "":
		return "string"
	}
	if _, err := strconv.ParseInt(v, 10, 64); err == nil {
		return "integer"
	}
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return "number"
	}
	return "string"
}

var versionSegRe = regexp.MustCompile(`(?i)^v[0-9]+(?:\.[0-9]+)*$`)

// apiVersion returns the API version segment of a path (e.g. /api/v2/x -> "v2"), or
// "" when the path carries no version segment.
func apiVersion(pathTemplate string) string {
	for _, seg := range strings.Split(pathTemplate, "/") {
		if versionSegRe.MatchString(seg) {
			return strings.ToLower(seg)
		}
	}
	return ""
}

// endpointConfidence scores how sure we are the endpoint is real, from its source
// and how often it was observed. Observed endpoints earn trust with repetition;
// a spec-only (inferred) endpoint is a documented hypothesis until seen in traffic.
func endpointConfidence(source string, observedCount int) (float64, string) {
	switch source {
	case "spec", "inferred":
		return 0.5, "inferred"
	default: // observed
		switch {
		case observedCount >= 3:
			return 0.95, "observed-strong"
		case observedCount == 2:
			return 0.8, "observed"
		default:
			return 0.65, "observed-single"
		}
	}
}

// mergeType combines a field's type across observations: identical types stay,
// conflicting ones become "mixed".
func mergeType(existing, next string) string {
	if existing == "" || existing == next {
		return next
	}
	if existing == "mixed" {
		return existing
	}
	return "mixed"
}

func topLevelTypes(body string) map[string]string {
	out := map[string]string{}
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &m) == nil {
		for k, v := range m {
			out[k] = inferJSONType(string(v))
		}
	}
	return out
}

func queryParamTypes(rawRequest string) map[string]string {
	out := map[string]string{}
	nl := strings.IndexAny(rawRequest, "\r\n")
	line := rawRequest
	if nl >= 0 {
		line = rawRequest[:nl]
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		return out
	}
	if i := strings.IndexByte(f[1], '?'); i >= 0 {
		for _, pair := range strings.Split(f[1][i+1:], "&") {
			k, v, _ := strings.Cut(pair, "=")
			if k != "" {
				out[k] = inferStringType(v)
			}
		}
	}
	return out
}

func (t *ToolSet) mobileAPIModel() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url": strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"offset":  intField("history offset (default 0)"),
			"count":   intField("max exchanges to scan (default 500)"),
		},
		"additionalProperties": false,
	}
	return readTool("mobile_api_model",
		"Enriched API model from captured traffic: per endpoint, the inferred TYPES of its query/body parameters and response fields, its API version (v1/v2/…), observed count and a numeric discovery confidence (observed endpoints gain confidence with repetition; spec-only endpoints are inferred). Complements mobile_api_harvest (inventory) and mobile_api_graph (relationships) with shapes and trust.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
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
			type agg struct {
				method, url, version string
				params               map[string]string
				response             map[string]string
				count                int
			}
			aggs := map[endpointKey]*agg{}
			for _, ex := range hist {
				method, canon, ok := exchangeEndpoint(ex)
				if !ok {
					continue
				}
				k := endpointKey{method, canon}
				g := aggs[k]
				if g == nil {
					g = &agg{method: method, url: canon, version: apiVersion(pathOf(canon)), params: map[string]string{}, response: map[string]string{}}
					aggs[k] = g
				}
				g.count++
				for name, typ := range queryParamTypes(ex.Request) {
					g.params["query:"+name] = mergeType(g.params["query:"+name], typ)
				}
				for name, typ := range topLevelTypes(httpBody(ex.Request)) {
					g.params["body:"+name] = mergeType(g.params["body:"+name], typ)
				}
				for name, typ := range topLevelTypes(httpBody(ex.Response)) {
					g.response[name] = mergeType(g.response[name], typ)
				}
			}
			type row struct {
				Method         string            `json:"method"`
				URL            string            `json:"url"`
				Version        string            `json:"version,omitempty"`
				ObservedCount  int               `json:"observed_count"`
				Confidence     float64           `json:"confidence"`
				ConfidenceTier string            `json:"confidence_tier"`
				ParamTypes     map[string]string `json:"param_types,omitempty"`
				ResponseSchema map[string]string `json:"response_schema,omitempty"`
			}
			rows := make([]row, 0, len(aggs))
			versions := map[string]bool{}
			for _, g := range aggs {
				conf, tier := endpointConfidence("observed", g.count)
				if g.version != "" {
					versions[g.version] = true
				}
				rows = append(rows, row{Method: g.method, URL: g.url, Version: g.version, ObservedCount: g.count, Confidence: conf, ConfidenceTier: tier, ParamTypes: g.params, ResponseSchema: g.response})
			}
			sort.Slice(rows, func(i, j int) bool {
				if rows[i].URL != rows[j].URL {
					return rows[i].URL < rows[j].URL
				}
				return rows[i].Method < rows[j].Method
			})
			vlist := make([]string, 0, len(versions))
			for v := range versions {
				vlist = append(vlist, v)
			}
			sort.Strings(vlist)
			out, _ := json.Marshal(map[string]any{
				"endpoints":    rows,
				"api_versions": vlist,
				"note":         "types inferred from observed values; confidence rises with observed_count. Spec-only endpoints (mobile_openapi_ingest) are inferred (0.5).",
			})
			return actool.Text(string(out)), nil
		})
}
