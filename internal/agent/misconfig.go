package agent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Aiz9/ripple/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// Security-misconfiguration probe (OWASP API8): CORS policy and missing security
// headers. Deterministic — a reflected cross-origin policy (especially with
// credentials) is the finding, read straight from the response headers.

// responseHeader returns a response header value (case-insensitive), or "".
func responseHeader(rawResponse, name string) string {
	head := rawResponse
	if i := strings.Index(rawResponse, "\r\n\r\n"); i >= 0 {
		head = rawResponse[:i]
	} else if i := strings.Index(rawResponse, "\n\n"); i >= 0 {
		head = rawResponse[:i]
	}
	for _, ln := range strings.Split(head, "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(ln, "\r"), ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// corsVerdict classifies a CORS response to an attacker-controlled Origin.
func corsVerdict(acao, acac, sentOrigin string) (vuln bool, severity, detail string) {
	acaoL := strings.ToLower(strings.TrimSpace(acao))
	creds := strings.EqualFold(strings.TrimSpace(acac), "true")
	origin := strings.ToLower(sentOrigin)
	switch {
	case acaoL == origin && origin != "" && creds:
		return true, "critical", "server reflects an arbitrary Origin (" + sentOrigin + ") AND allows credentials — any site can read authenticated responses"
	case acaoL == origin && origin != "":
		return true, "high", "server reflects an arbitrary Origin (" + sentOrigin + ") in Access-Control-Allow-Origin"
	case acaoL == "null" && origin == "null":
		return true, "high", "server allows the null Origin (reachable from sandboxed iframes / local files)"
	case acaoL == "*" && creds:
		return true, "medium", "wildcard Access-Control-Allow-Origin together with Allow-Credentials (misconfigured policy)"
	default:
		return false, "", ""
	}
}

// recommendedSecurityHeaders maps a header to why it matters; absence is reported
// (informational) for https API responses.
var recommendedSecurityHeaders = map[string]string{
	"Strict-Transport-Security": "no HSTS — TLS downgrade / sslstrip risk",
	"X-Content-Type-Options":    "no nosniff — MIME-type confusion",
	"Cache-Control":             "no Cache-Control — sensitive responses may be cached",
}

func (t *ToolSet) mobileMisconfigProbe() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":       strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"history_index": intField("history index of a captured request to test for CORS / header misconfiguration"),
		},
		"required":             []any{"history_index"},
		"additionalProperties": false,
	}
	return writeTool("mobile_misconfig_probe",
		"Security-misconfiguration tester (OWASP API8). Replays a captured request with an attacker-controlled Origin and reads the CORS policy: a server that reflects an arbitrary Origin (especially with Access-Control-Allow-Credentials: true) or allows the null origin is a finding. Also reports missing security response headers (HSTS, X-Content-Type-Options, Cache-Control). Deterministic — decided from the response headers.",
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
			recordCoverage(t.taskID, coverageKey(req), "misconfig")
			port := 443
			if !req.TLS {
				port = 80
			}
			send := func(origin string) (string, error) {
				r := applyIdentityHeaders(req.Request, map[string]string{"Origin": origin})
				return c.SendRequest(ctx, req.Host, port, req.TLS, r)
			}

			const attacker = "https://evil.attacker.example"
			var corsHits []string
			var sev string
			for _, origin := range []string{attacker, "null"} {
				resp, e := send(origin)
				if e != nil {
					continue
				}
				acao := responseHeader(resp, "Access-Control-Allow-Origin")
				acac := responseHeader(resp, "Access-Control-Allow-Credentials")
				if vuln, s, detail := corsVerdict(acao, acac, origin); vuln {
					corsHits = append(corsHits, detail)
					if sev == "" || s == "critical" {
						sev = s
					}
				}
			}
			// Missing security headers on the baseline response.
			var missing []string
			if req.TLS {
				for h, why := range recommendedSecurityHeaders {
					if responseHeader(req.Response, h) == "" {
						missing = append(missing, h+" ("+why+")")
					}
				}
			}

			result := map[string]any{
				"endpoint":                 req.Method + " " + req.Host + req.Path,
				"cors_issues":              corsHits,
				"missing_security_headers": missing,
				"note":                     "CORS issues are findings; missing headers are hardening observations.",
			}
			if len(corsHits) > 0 {
				if sev == "" {
					sev = "high"
				}
				fb := &findingBlock{
					VulnClass:        "Security Misconfiguration — permissive CORS policy",
					Name:             "Permissive CORS on " + req.Method + " " + req.Path,
					Severity:         sev,
					Summary:          "The server returns a cross-origin policy that trusts attacker-controlled origins.",
					AffectedEndpoint: req.Host + req.Path,
					Method:           req.Method,
					Preconditions:    "A captured request to the endpoint.",
					Reproduction: append([]string{"Replay " + req.Method + " " + req.Path + " with an attacker Origin header; observe the CORS response:"},
						corsHits...),
					Expected:           "Access-Control-Allow-Origin is restricted to trusted origins; credentials are not exposed to arbitrary origins.",
					Actual:             strings.Join(corsHits, "; "),
					Impact:             "A malicious website can read this endpoint's authenticated responses in the victim's browser (cross-origin data theft).",
					Remediation:        "Allow-list exact trusted origins server-side; never reflect the request Origin; never combine Allow-Credentials with a wildcard or reflected origin; reject the null origin.",
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
