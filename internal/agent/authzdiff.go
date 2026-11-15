package agent

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// Deterministic authorization differential verifier.
//
// The LLM-judged replay primitive (mobile_traffic_replay + as_role) could only
// return a raw response for the model to eyeball — which made "2xx therefore IDOR"
// a standing temptation. This module replays an owner's captured request as a
// different principal (and, optionally, with auth stripped) and decides the
// verdict with deterministic rules over observable evidence: status codes across
// owner/attacker/unauth, body similarity, and whether the owner's resource
// identifiers reappear in the other principal's response. A 2xx alone never
// confirms; only disclosure (owner's data returned to a principal that should not
// see it) or missing enforcement does.

// Authorization verdicts.
const (
	authzVulnerable    = "vulnerable"     // owner's resource/data disclosed to the other principal
	authzNotVulnerable = "not_vulnerable" // access control enforced (denied) for the other principal
	authzInconclusive  = "inconclusive"   // 2xx but no evidence of owner-data disclosure; needs semantic review
	authzNoBaseline    = "no_baseline"    // owner's own request did not yield a successful resource fetch
)

var authHeaderNames = []string{"authorization", "cookie", "x-api-key", "x-auth-token", "x-access-token"}

// uuidRe matches a canonical UUID. Other id shapes are decided in isResourceID.
var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var alnumHandleRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,}$`)

// isResourceID reports whether tok looks like a resource identifier a BOLA attack
// pivots on: a digit run, a UUID, or a long opaque handle. The handle branch
// requires a digit so dictionary path words ("accounts", "balance") are excluded.
// shortcut: pure-alpha hashes (no digit) are not treated as IDs; upgrade if a
// target uses such object references.
func isResourceID(tok string) bool {
	if len(tok) < 2 {
		return false
	}
	if uuidRe.MatchString(tok) {
		return true
	}
	allDigit := true
	for _, r := range tok {
		if r < '0' || r > '9' {
			allDigit = false
			break
		}
	}
	if allDigit {
		return true
	}
	return alnumHandleRe.MatchString(tok) && strings.ContainsAny(tok, "0123456789")
}

// stripAuthHeaders removes auth-bearing header lines so a request can be replayed
// as an anonymous principal (missing-authentication test).
func stripAuthHeaders(raw string) string {
	head, body := raw, ""
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		head, body = raw[:i], raw[i:]
	} else if i := strings.Index(raw, "\n\n"); i >= 0 {
		head, body = raw[:i], "\r\n\r\n"+raw[i+2:]
	}
	lines := strings.Split(head, "\n")
	kept := make([]string, 0, len(lines))
	for i, line := range lines {
		l := strings.TrimRight(line, "\r")
		if i == 0 {
			kept = append(kept, l)
			continue
		}
		if name, _, ok := strings.Cut(l, ":"); ok {
			lname := strings.ToLower(strings.TrimSpace(name))
			drop := false
			for _, a := range authHeaderNames {
				if lname == a {
					drop = true
					break
				}
			}
			if drop {
				continue
			}
		}
		kept = append(kept, l)
	}
	if body == "" {
		body = "\r\n\r\n"
	}
	return strings.Join(kept, "\r\n") + body
}

// httpStatus parses the numeric status code from a raw HTTP response (0 if absent).
func httpStatus(raw string) int {
	nl := strings.IndexAny(raw, "\r\n")
	line := raw
	if nl >= 0 {
		line = raw[:nl]
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		return 0
	}
	code, err := strconv.Atoi(f[1])
	if err != nil {
		return 0
	}
	return code
}

// httpBody returns the body portion of a raw HTTP message.
func httpBody(raw string) string {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[i+4:]
	}
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[i+2:]
	}
	return ""
}

// trigrams returns the set of 3-grams of s.
func trigrams(s string) map[string]struct{} {
	m := make(map[string]struct{})
	r := []rune(s)
	if len(r) < 3 {
		if len(r) > 0 {
			m[string(r)] = struct{}{}
		}
		return m
	}
	for i := 0; i+3 <= len(r); i++ {
		m[string(r[i:i+3])] = struct{}{}
	}
	return m
}

// bodySimilarity is the Jaccard similarity of the two bodies' 3-gram sets (0..1).
// Two empty bodies are identical (1.0); one empty is 0.
func bodySimilarity(a, b string) float64 {
	ta, tb := trigrams(a), trigrams(b)
	if len(ta) == 0 && len(tb) == 0 {
		return 1.0
	}
	if len(ta) == 0 || len(tb) == 0 {
		return 0.0
	}
	inter := 0
	for k := range ta {
		if _, ok := tb[k]; ok {
			inter++
		}
	}
	union := len(ta) + len(tb) - inter
	if union == 0 {
		return 0.0
	}
	return float64(inter) / float64(union)
}

// resourceIDs extracts identifier-like tokens from a raw request's path and query:
// the owner's object references a BOLA attack targets.
func resourceIDs(rawRequest string) []string {
	nl := strings.IndexAny(rawRequest, "\r\n")
	line := rawRequest
	if nl >= 0 {
		line = rawRequest[:nl]
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		return nil
	}
	target := f[1]
	path, query := target, ""
	if i := strings.IndexByte(target, '?'); i >= 0 {
		path, query = target[:i], target[i+1:]
	}
	seen := map[string]struct{}{}
	var ids []string
	add := func(tok string) {
		tok = strings.TrimSpace(tok)
		if tok == "" || !isResourceID(tok) {
			return
		}
		if _, ok := seen[tok]; ok {
			return
		}
		seen[tok] = struct{}{}
		ids = append(ids, tok)
	}
	for _, seg := range strings.Split(path, "/") {
		if dec, err := url.PathUnescape(seg); err == nil {
			seg = dec
		}
		add(seg)
	}
	if vals, err := url.ParseQuery(query); err == nil {
		for _, vs := range vals {
			for _, v := range vs {
				add(v)
			}
		}
	}
	return ids
}

// sharedIDs returns the owner resource IDs that reappear in body.
func sharedIDs(body string, ids []string) []string {
	var out []string
	for _, id := range ids {
		if strings.Contains(body, id) {
			out = append(out, id)
		}
	}
	return out
}

// classifyAccess decides the authorization verdict for one candidate principal
// (attacker or anonymous) replaying the owner's request. ownerStatus is the
// owner's own response status (the baseline), candStatus/candBody the candidate's.
// ownerBody is the owner's baseline response body. The rule set never confirms on
// status code alone: a 2xx is only vulnerable when the owner's data is actually
// disclosed (near-identical body, or owner resource IDs echoed back).
func classifyAccess(ownerStatus, candStatus int, ownerBody, candBody string, ownerIDs []string) (verdict, reason string, similarity float64, shared []string) {
	if ownerStatus < 200 || ownerStatus >= 300 {
		return authzNoBaseline, "owner's own request did not return 2xx; cannot establish a baseline of legitimately-owned data", 0, nil
	}
	similarity = bodySimilarity(ownerBody, candBody)
	shared = sharedIDs(candBody, ownerIDs)
	switch {
	case candStatus == 401 || candStatus == 403:
		return authzNotVulnerable, "access control enforced: candidate principal was denied (" + strconv.Itoa(candStatus) + ")", similarity, shared
	case candStatus == 404:
		return authzNotVulnerable, "object not disclosed to candidate principal (404)", similarity, shared
	case candStatus >= 200 && candStatus < 300:
		if len(candBody) >= 16 && similarity >= 0.9 {
			return authzVulnerable, "owner's resource returned to candidate principal (body similarity " + strconv.FormatFloat(similarity, 'f', 2, 64) + ")", similarity, shared
		}
		if len(candBody) >= 16 && len(shared) > 0 {
			return authzVulnerable, "owner's resource identifiers echoed in candidate response: " + strings.Join(shared, ", "), similarity, shared
		}
		return authzInconclusive, "candidate got 2xx but no evidence of owner-data disclosure (body differs; may be the candidate's own data, a shared resource, or empty) — needs semantic review", similarity, shared
	default:
		return authzInconclusive, "candidate returned status " + strconv.Itoa(candStatus) + "; not a clear allow or deny", similarity, shared
	}
}

// authzFindingBlock builds a ready-to-file finding from the candidate results, or
// nil when nothing was deterministically confirmed. Only 'vulnerable' candidates
// produce a finding (verification_status=confirmed); inconclusive/denied do not,
// so an AI suspicion never becomes a finding without deterministic proof.
func authzFindingBlock(method, host, path string, candidates []authzCandidate) *findingBlock {
	var confirmed []authzCandidate
	unauth := false
	for _, c := range candidates {
		if c.Verdict == authzVulnerable {
			confirmed = append(confirmed, c)
			if c.Principal == "unauthenticated" {
				unauth = true
			}
		}
	}
	if len(confirmed) == 0 {
		return nil
	}
	vulnClass := "BOLA / IDOR (broken object-level authorization)"
	if unauth {
		if len(confirmed) == 1 {
			vulnClass = "Broken Authentication (protected resource reachable without authentication)"
		} else {
			vulnClass = "Broken Authorization (BOLA/IDOR + missing authentication)"
		}
	}
	var actual strings.Builder
	repro := []string{"Authenticate as the resource owner and issue " + method + " " + path + "; observe a 2xx response returning the owner's resource (baseline)."}
	for _, c := range confirmed {
		principal := c.Principal
		if c.Principal == "unauthenticated" {
			repro = append(repro, "Replay the identical request with all authentication headers removed.")
		} else {
			repro = append(repro, "Replay the identical request swapping in "+principal+"'s credentials.")
		}
		actual.WriteString(principal + ": HTTP " + strconv.Itoa(c.Status) + " — " + c.Reason + ". ")
	}
	repro = append(repro, "Compare the response to the owner baseline (deterministic differential: body similarity / owner resource-id echo).")
	return &findingBlock{
		VulnClass:          vulnClass,
		Name:               "Broken object-level authorization on " + method + " " + path,
		Severity:           "high",
		Summary:            "A principal that does not own the resource received the owner's data when replaying the owner's request as another identity / unauthenticated.",
		AffectedEndpoint:   host + path,
		Method:             method,
		Preconditions:      "Two authorized test identities (or an anonymous client); a captured request in which the owner legitimately accesses its own resource.",
		Reproduction:       repro,
		Expected:           "A non-owner (or unauthenticated) principal is denied with 401/403/404 and receives none of the owner's data.",
		Actual:             strings.TrimSpace(actual.String()),
		Impact:             "Unauthorized disclosure or modification of another user's resource (BOLA/IDOR). On a financial app this exposes other customers' accounts, balances, or transactions.",
		Remediation:        "Enforce object-level authorization server-side on every request: verify the authenticated principal owns or is permitted the referenced object before returning or mutating it; never rely on client-supplied object IDs alone.",
		VerificationStatus: "confirmed",
	}
}

type authzCandidate struct {
	Principal  string   `json:"principal"`
	Status     int      `json:"status"`
	Verdict    string   `json:"verdict"`
	Reason     string   `json:"reason"`
	Similarity float64  `json:"body_similarity"`
	SharedIDs  []string `json:"shared_owner_ids,omitempty"`
}

func (t *ToolSet) mobileAuthzDiff() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":       strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"history_index": intField("absolute history index (from mobile_traffic_history) of the OWNER's captured exchange: identity A legitimately fetching/modifying its own resource — this is the baseline"),
			"as_role":       strField("registered identity (mobile_identity_set) to replay the owner's request AS — the attacker principal B who should NOT have access"),
			"also_unauth":   map[string]any{"type": "boolean", "description": "also replay with all auth headers stripped, to test missing-authentication enforcement (default true)"},
		},
		"required":             []any{"history_index", "as_role"},
		"additionalProperties": false,
	}
	return writeTool("mobile_authz_diff",
		"Deterministic IDOR/BOLA verifier. Takes the OWNER's captured exchange (history_index) as the baseline, replays that exact request as a DIFFERENT identity (as_role) and (by default) with auth stripped, then decides the verdict with fixed rules — not by eye. A 2xx never confirms on its own: a candidate is 'vulnerable' only when the owner's resource is actually disclosed (near-identical response body, or the owner's resource identifiers echoed back); a denial (401/403/404) is 'not_vulnerable'; a 2xx without disclosure evidence is 'inconclusive' (review semantically). Returns per-principal status, verdict, reason, body similarity and shared owner IDs — reproducible evidence for the finding.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				MCPURL       string `json:"mcp_url"`
				HistoryIndex *int   `json:"history_index"`
				AsRole       string `json:"as_role"`
				AlsoUnauth   *bool  `json:"also_unauth"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if a.HistoryIndex == nil || *a.HistoryIndex < 0 {
				return actool.Errorf("history_index (>= 0) is required"), nil
			}
			if strings.TrimSpace(a.AsRole) == "" {
				return actool.Errorf("as_role is required"), nil
			}
			id, ok := getIdentity(t.taskID, a.AsRole)
			if !ok {
				return errf("unknown identity role %q; register it with mobile_identity_set first", a.AsRole), nil
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
			owner := ex[0]
			ownerStatus := httpStatus(owner.Response)
			ownerBody := httpBody(owner.Response)
			ownerIDs := resourceIDs(owner.Request)

			port := 443
			if !owner.TLS {
				port = 80
			}

			candidates := []authzCandidate{}
			// Attacker principal B.
			attackerReq := applyIdentityHeaders(owner.Request, id.Headers)
			attackerResp, aerr := c.SendRequest(ctx, owner.Host, port, owner.TLS, attackerReq)
			if aerr != nil {
				return errf("replay as %s: %v", a.AsRole, aerr), nil
			}
			v, reason, sim, shared := classifyAccess(ownerStatus, httpStatus(attackerResp), ownerBody, httpBody(attackerResp), ownerIDs)
			candidates = append(candidates, authzCandidate{Principal: "role:" + a.AsRole, Status: httpStatus(attackerResp), Verdict: v, Reason: reason, Similarity: sim, SharedIDs: shared})

			// Anonymous principal (missing-authentication).
			unauth := a.AlsoUnauth == nil || *a.AlsoUnauth
			if unauth {
				anonReq := stripAuthHeaders(owner.Request)
				anonResp, uerr := c.SendRequest(ctx, owner.Host, port, owner.TLS, anonReq)
				if uerr == nil {
					uv, ureason, usim, ushared := classifyAccess(ownerStatus, httpStatus(anonResp), ownerBody, httpBody(anonResp), ownerIDs)
					candidates = append(candidates, authzCandidate{Principal: "unauthenticated", Status: httpStatus(anonResp), Verdict: uv, Reason: ureason, Similarity: usim, SharedIDs: ushared})
				}
			}

			// Downgrade expected shared/role access so it is not reported as IDOR.
			if _, canon, ok := exchangeEndpoint(owner); ok {
				t.applyAuthzExpectations(owner.Method, pathOf(canon), candidates)
			}

			overall := authzNotVulnerable
			for _, c := range candidates {
				if c.Verdict == authzVulnerable {
					overall = authzVulnerable
					break
				}
				if c.Verdict == authzInconclusive || c.Verdict == authzNoBaseline {
					overall = authzInconclusive
				}
			}
			result := map[string]any{
				"owner": map[string]any{
					"host":          owner.Host,
					"method":        owner.Method,
					"path":          owner.Path,
					"status":        ownerStatus,
					"history_index": *a.HistoryIndex,
					"resource_ids":  ownerIDs,
				},
				"candidates": candidates,
				"overall":    overall,
				"note":       "Verdict is deterministic over observed evidence; 'inconclusive' means a 2xx without proof of owner-data disclosure, not a vulnerability.",
			}
			if fb := authzFindingBlock(owner.Method, owner.Host, owner.Path, candidates); fb != nil {
				_, canon, _ := exchangeEndpoint(owner)
				if id, ok := t.fileFinding(ctx, fb, t.endpointAssetID(canon, owner.Method)); ok {
					fb.FiledFindingID = id
				}
				result["finding"] = fb
			}
			out, _ := json.Marshal(result)
			return actool.Text(string(out)), nil
		})
}
