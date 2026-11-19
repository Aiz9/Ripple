package agent

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/Aiz9/ripple/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// Batch authorization sweep: run the deterministic authz differential (authzdiff)
// across the whole captured surface automatically, instead of one exchange at a
// time. For every distinct authenticated endpoint seen in history it replays the
// owner's request as every OTHER registered identity (and unauthenticated) and
// classifies each with the same fixed rules. This is object-level authorization
// testing at inventory scale — the "drive BOLA across everything" step.

// identityOwnsRequest reports whether the raw request already carries exactly this
// identity's auth material — i.e. this identity is the request's owner, so it must
// be excluded from the sweep (replaying an owner as itself is not an attack and
// would self-match as a false positive).
func identityOwnsRequest(raw string, id Identity) bool {
	if len(id.Headers) == 0 {
		return false
	}
	present := map[string]string{}
	for k, v := range extractAuthHeaders(raw) {
		present[strings.ToLower(k)] = strings.TrimSpace(v)
	}
	for k, v := range id.Headers {
		if present[strings.ToLower(k)] != strings.TrimSpace(v) {
			return false
		}
	}
	return true
}

// ownerExchanges selects one representative authenticated, successful exchange per
// (method, normalized endpoint) from history — the candidate owner baselines to
// sweep. Deduping by template keeps the sweep bounded regardless of traffic volume.
func ownerExchanges(hist []devicelab.Exchange) []devicelab.Exchange {
	seen := map[endpointKey]bool{}
	var out []devicelab.Exchange
	for _, ex := range hist {
		if !requestHasAuth(ex.Request) {
			continue
		}
		if s := httpStatus(ex.Response); s < 200 || s >= 300 {
			continue
		}
		method, canon, ok := exchangeEndpoint(ex)
		if !ok {
			continue
		}
		k := endpointKey{method, canon}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, ex)
	}
	return out
}

// pathOf returns the path portion of a canonical scheme://host/path URL.
func pathOf(canon string) string {
	s := canon
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[i:]
	}
	return "/"
}

func (t *ToolSet) mobileAuthzSweep() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":     strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"offset":      intField("history offset to start from (default 0)"),
			"count":       intField("max exchanges to scan (default 500)"),
			"also_unauth": map[string]any{"type": "boolean", "description": "also test each endpoint unauthenticated (default true)"},
		},
		"additionalProperties": false,
	}
	return writeTool("mobile_authz_sweep",
		"Batch IDOR/BOLA across the whole captured surface. For each distinct authenticated+successful endpoint in Burp history, replays the owner's request as every OTHER registered identity (owner is auto-excluded by auth-header match) and, by default, unauthenticated — classifying each with the deterministic authz rules (2xx alone never confirms). Register identities first (mobile_identity_set). Returns a per-endpoint × per-principal verdict matrix; investigate every 'vulnerable' and review 'inconclusive'. Use mobile_authz_diff for a single targeted check.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				MCPURL     string `json:"mcp_url"`
				Offset     int    `json:"offset"`
				Count      int    `json:"count"`
				AlsoUnauth *bool  `json:"also_unauth"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			ids := listIdentities(t.taskID)
			if len(ids) == 0 {
				return actool.Errorf("no identities registered; register at least one with mobile_identity_set first"), nil
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
			owners := ownerExchanges(hist)
			unauth := a.AlsoUnauth == nil || *a.AlsoUnauth

			type epResult struct {
				Method     string            `json:"method"`
				URL        string            `json:"url"`
				OwnerRole  string            `json:"owner_role,omitempty"`
				Candidates []authzCandidate  `json:"candidates"`
				Verdict    string            `json:"verdict"`
				Access     map[string]string `json:"role_access,omitempty"` // role -> owner|accessible|denied|maybe
				Finding    *findingBlock     `json:"finding,omitempty"`
			}
			var results []epResult
			vulnCount := 0
			filed := 0
			for _, owner := range owners {
				method, canon, _ := exchangeEndpoint(owner)
				recordCoverage(t.taskID, method+" "+pathOf(canon), "authz")
				ownerStatus := httpStatus(owner.Response)
				ownerBody := httpBody(owner.Response)
				ownerIDs := resourceIDs(owner.Request)
				port := 443
				if !owner.TLS {
					port = 80
				}
				ep := epResult{Method: method, URL: canon, Verdict: authzNotVulnerable}
				for _, id := range ids {
					if identityOwnsRequest(owner.Request, id) {
						ep.OwnerRole = id.Role
						continue
					}
					req := applyIdentityHeaders(owner.Request, id.Headers)
					resp, serr := c.SendRequest(ctx, owner.Host, port, owner.TLS, req)
					if serr != nil {
						continue
					}
					v, reason, sim, shared := classifyAccess(ownerStatus, httpStatus(resp), ownerBody, httpBody(resp), ownerIDs)
					ep.Candidates = append(ep.Candidates, authzCandidate{Principal: "role:" + id.Role, Status: httpStatus(resp), Verdict: v, Reason: reason, Similarity: sim, SharedIDs: shared})
				}
				if unauth {
					resp, serr := c.SendRequest(ctx, owner.Host, port, owner.TLS, stripAuthHeaders(owner.Request))
					if serr == nil {
						v, reason, sim, shared := classifyAccess(ownerStatus, httpStatus(resp), ownerBody, httpBody(resp), ownerIDs)
						ep.Candidates = append(ep.Candidates, authzCandidate{Principal: "unauthenticated", Status: httpStatus(resp), Verdict: v, Reason: reason, Similarity: sim, SharedIDs: shared})
					}
				}
				t.applyAuthzExpectations(method, pathOf(canon), ep.Candidates)
				// Build the role×function access row (BFLA matrix).
				ep.Access = map[string]string{}
				if ep.OwnerRole != "" {
					ep.Access[ep.OwnerRole] = "owner"
				}
				for _, cand := range ep.Candidates {
					role := strings.TrimPrefix(cand.Principal, "role:")
					switch cand.Verdict {
					case authzVulnerable:
						ep.Access[role] = "accessible"
					case authzNotVulnerable:
						ep.Access[role] = "denied"
					default:
						ep.Access[role] = "maybe"
					}
				}
				for _, cand := range ep.Candidates {
					if cand.Verdict == authzVulnerable {
						ep.Verdict = authzVulnerable
						break
					}
					if cand.Verdict == authzInconclusive {
						ep.Verdict = authzInconclusive
					}
				}
				if ep.Verdict == authzVulnerable {
					vulnCount++
					ep.Finding = authzFindingBlock(method, owner.Host, pathOf(canon), ep.Candidates)
					if id, ok := t.fileFinding(ctx, ep.Finding, t.endpointAssetID(canon, method)); ok {
						ep.Finding.FiledFindingID = id
						filed++
					}
				}
				results = append(results, ep)
			}
			sort.Slice(results, func(i, j int) bool {
				if results[i].URL != results[j].URL {
					return results[i].URL < results[j].URL
				}
				return results[i].Method < results[j].Method
			})
			out, _ := json.Marshal(map[string]any{
				"endpoints_tested":  len(results),
				"identities":        len(ids),
				"vulnerable":        vulnCount,
				"findings_filed":    filed,
				"ownership_map":     ownershipMap(t.taskID),
				"exchanges_scanned": len(hist),
				"results":           results,
			})
			return actool.Text(string(out)), nil
		})
}
