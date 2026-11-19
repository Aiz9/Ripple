package agent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Aiz9/ripple/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// Authentication lifecycle tests: rate-limiting / brute-force throttling, and
// session invalidation after logout/rotation. Both decide deterministically from
// the server's responses — a missing throttle or a still-accepted dead token is
// the finding, never an assumption.

var throttleMarkers = []string{"too many", "rate limit", "ratelimit", "slow down", "locked",
	"lockout", "try again later", "temporarily blocked", "account locked", "captcha"}

// rateLimited reports whether the server throttled the burst: a 429/423 status, or
// a throttle/lockout message in any body.
func rateLimited(statuses []int, bodies []string) bool {
	for _, s := range statuses {
		if s == 429 || s == 423 {
			return true
		}
	}
	for _, b := range bodies {
		lb := strings.ToLower(b)
		for _, m := range throttleMarkers {
			if strings.Contains(lb, m) {
				return true
			}
		}
	}
	return false
}

func (t *ToolSet) mobileRateLimitProbe() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":       strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"history_index": intField("history index of the auth/sensitive request to hammer (login, OTP verify, password reset)"),
			"attempts":      intField("number of rapid repeats to send (default 20)"),
		},
		"required":             []any{"history_index"},
		"additionalProperties": false,
	}
	return writeTool("mobile_ratelimit_probe",
		"Rate-limiting / brute-force throttling tester. Rapidly re-sends a captured auth or sensitive request (login, OTP verify, password reset) N times and checks whether the server ever throttles (429/423, or a lockout/'too many attempts'/captcha response). If none of the attempts are throttled, rate-limiting is missing — the endpoint is brute-forceable (credential stuffing, OTP guessing). SANDBOX ONLY; use test accounts.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				MCPURL       string `json:"mcp_url"`
				HistoryIndex *int   `json:"history_index"`
				Attempts     int    `json:"attempts"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if a.HistoryIndex == nil || *a.HistoryIndex < 0 {
				return actool.Errorf("history_index (>= 0) is required"), nil
			}
			if a.Attempts <= 1 {
				a.Attempts = 20
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
			port := 443
			if !req.TLS {
				port = 80
			}
			statuses := make([]int, 0, a.Attempts)
			bodies := make([]string, 0, a.Attempts)
			for i := 0; i < a.Attempts; i++ {
				resp, e := c.SendRequest(ctx, req.Host, port, req.TLS, req.Request)
				if e != nil {
					continue
				}
				statuses = append(statuses, httpStatus(resp))
				bodies = append(bodies, httpBody(resp))
			}
			recordCoverage(t.taskID, coverageKey(req), "rate-limit")
			throttled := rateLimited(statuses, bodies)
			result := map[string]any{
				"endpoint":  req.Method + " " + req.Host + req.Path,
				"attempts":  len(statuses),
				"throttled": throttled,
				"statuses":  statuses,
				"note":      "no throttle across all attempts means rate-limiting is missing on this endpoint.",
			}
			if !throttled && len(statuses) >= 5 {
				fb := &findingBlock{
					VulnClass:        "Missing rate limiting / brute-force protection",
					Name:             "No rate limiting on " + req.Method + " " + req.Path,
					Severity:         "high",
					Summary:          "The endpoint accepted many rapid repeats with no throttling or lockout, so it is brute-forceable.",
					AffectedEndpoint: req.Host + req.Path,
					Method:           req.Method,
					Preconditions:    "A captured auth/sensitive request and an authorized test account.",
					Reproduction: []string{
						"Replay " + req.Method + " " + req.Path + " " + itoa(len(statuses)) + " times in quick succession.",
						"Observe no 429/423, lockout or captcha across any attempt.",
					},
					Expected:           "After a small number of attempts the server throttles (429/423), locks out, or requires a captcha.",
					Actual:             itoa(len(statuses)) + " rapid attempts, none throttled.",
					Impact:             "Credential stuffing, password/OTP brute force, and resource abuse against this endpoint.",
					Remediation:        "Enforce server-side rate limiting and progressive lockout per account and per source; add captcha/step-up on repeated failures; cap OTP attempts.",
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

func (t *ToolSet) mobileSessionProbe() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":          strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"history_index":    intField("history index of an authenticated request whose token you have since invalidated (logged out / rotated / expired)"),
			"expected_invalid": map[string]any{"type": "boolean", "description": "set true after you have logged out or rotated the token — the captured token SHOULD now be rejected (default true)"},
		},
		"required":             []any{"history_index"},
		"additionalProperties": false,
	}
	return writeTool("mobile_session_probe",
		"Session invalidation tester. Replays a captured authenticated request AFTER you have logged out / rotated / expired its token. If the server still returns the user's data, the session was not invalidated server-side (logout is client-only / token still live) — a session-management failure. Perform the logout first, then run this on the pre-logout request. SANDBOX ONLY.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				MCPURL          string `json:"mcp_url"`
				HistoryIndex    *int   `json:"history_index"`
				ExpectedInvalid *bool  `json:"expected_invalid"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if a.HistoryIndex == nil || *a.HistoryIndex < 0 {
				return actool.Errorf("history_index (>= 0) is required"), nil
			}
			expInvalid := a.ExpectedInvalid == nil || *a.ExpectedInvalid
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
			port := 443
			if !req.TLS {
				port = 80
			}
			resp, e := c.SendRequest(ctx, req.Host, port, req.TLS, req.Request)
			if e != nil {
				return errf("replay: %v", e), nil
			}
			recordCoverage(t.taskID, coverageKey(req), "session")
			outcome := classifyTxn(httpStatus(resp), httpBody(resp))
			stillValid := outcome == txnAccepted
			result := map[string]any{
				"endpoint":          req.Method + " " + req.Host + req.Path,
				"status":            httpStatus(resp),
				"token_still_valid": stillValid,
				"expected_invalid":  expInvalid,
				"note":              "run this AFTER logout/rotation; a still-valid token means the session was not invalidated server-side.",
			}
			if expInvalid && stillValid {
				fb := &findingBlock{
					VulnClass:        "Broken Session Management (session not invalidated)",
					Name:             "Session not invalidated after logout on " + req.Method + " " + req.Path,
					Severity:         "high",
					Summary:          "A token the user has logged out / rotated still grants access, so logout does not invalidate the session server-side.",
					AffectedEndpoint: req.Host + req.Path,
					Method:           req.Method,
					Preconditions:    "A captured authenticated request; the user then logs out / rotates the token.",
					Reproduction: []string{
						"Capture an authenticated request to " + req.Method + " " + req.Path + ".",
						"Log out (or rotate/expire the token) through the app.",
						"Replay the captured request with the old token; observe it is still accepted (HTTP " + itoa(httpStatus(resp)) + ").",
					},
					Expected:           "After logout/rotation the old token is rejected (401).",
					Actual:             "The old token still returns the user's data (HTTP " + itoa(httpStatus(resp)) + ").",
					Impact:             "Stolen or logged-out tokens remain usable — session hijacking persists past logout.",
					Remediation:        "Invalidate sessions/tokens server-side on logout and rotation (server-side session store or token revocation list); do not rely on client-side token deletion.",
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
