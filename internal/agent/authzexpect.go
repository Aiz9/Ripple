package agent

import (
	"context"
	"encoding/json"
	"path"
	"sort"
	"strings"
	"sync"

	actool "github.com/Autumn-27/norma/tool"
)

// Configurable authorization expectations.
//
// The differential verifier flags "vulnerable" whenever a principal that is not
// the owner receives the owner's data. That is correct for private resources but
// wrong for resources that are LEGITIMATELY shared — a public endpoint, one open
// to any authenticated user, or an administrative view. Expectations let the
// operator declare those cases per task so expected access is not reported as a
// finding; everything else still is. Without any expectation registered, behavior
// is unchanged (nothing is downgraded).

// authzExpectation declares that a (method, path-pattern) is expected to be
// reachable by certain principals. Method "" matches any method. Pattern is a
// shell-glob (path.Match) over the normalized route template, e.g. "/announcements",
// "/shared/*", "/accounts/{id}/public".
type authzExpectation struct {
	Method     string   `json:"method,omitempty"`
	Pattern    string   `json:"pattern"`
	SharedWith []string `json:"shared_with"` // public | authenticated | <role name>
}

var (
	authzExpectMu    sync.Mutex
	authzExpectStore = map[int64][]authzExpectation{} // taskID -> expectations
)

func addAuthzExpectation(taskID int64, e authzExpectation) {
	authzExpectMu.Lock()
	defer authzExpectMu.Unlock()
	authzExpectStore[taskID] = append(authzExpectStore[taskID], e)
}

func listAuthzExpectations(taskID int64) []authzExpectation {
	authzExpectMu.Lock()
	defer authzExpectMu.Unlock()
	out := make([]authzExpectation, len(authzExpectStore[taskID]))
	copy(out, authzExpectStore[taskID])
	return out
}

// principalAllowed reports whether a principal ("role:<name>" or "unauthenticated")
// is covered by a shared_with list. "public" covers everyone; "authenticated"/"any"
// covers any registered role; "unauthenticated"/"anonymous" covers the anon
// principal; any other token is a specific role name.
func principalAllowed(sharedWith []string, principal string) bool {
	isRole := strings.HasPrefix(principal, "role:")
	roleName := strings.TrimPrefix(principal, "role:")
	for _, t := range sharedWith {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "public", "*", "everyone":
			return true
		case "authenticated", "any", "any_authenticated", "any_auth":
			if isRole {
				return true
			}
		case "unauthenticated", "anonymous", "anon", "unauth":
			if principal == "unauthenticated" {
				return true
			}
		default:
			if isRole && strings.EqualFold(roleName, strings.TrimSpace(t)) {
				return true
			}
		}
	}
	return false
}

// matchExpectation reports whether some expectation declares (method, path) as
// expected access for principal.
func matchExpectation(exps []authzExpectation, method, pathTemplate, principal string) bool {
	for _, e := range exps {
		if e.Method != "" && !strings.EqualFold(e.Method, method) {
			continue
		}
		if ok, _ := path.Match(e.Pattern, pathTemplate); !ok && e.Pattern != pathTemplate {
			continue
		}
		if principalAllowed(e.SharedWith, principal) {
			return true
		}
	}
	return false
}

// applyAuthzExpectations downgrades each 'vulnerable' candidate to 'not_vulnerable'
// when the (method, pathTemplate, principal) is declared as expected access for
// this task. Returns the number downgraded.
func (t *ToolSet) applyAuthzExpectations(method, pathTemplate string, candidates []authzCandidate) int {
	exps := listAuthzExpectations(t.taskID)
	if len(exps) == 0 {
		return 0
	}
	n := 0
	for i := range candidates {
		if candidates[i].Verdict != authzVulnerable {
			continue
		}
		if matchExpectation(exps, method, pathTemplate, candidates[i].Principal) {
			candidates[i].Verdict = authzNotVulnerable
			candidates[i].Reason = "expected shared/role access per configured authorization expectation (" + method + " " + pathTemplate + ")"
			n++
		}
	}
	return n
}

func (t *ToolSet) mobileAuthzExpect() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"method":      strField("HTTP method this applies to; omit for any method"),
			"pattern":     strField("route pattern over the NORMALIZED path (ids as {id}); shell glob, e.g. /announcements, /shared/*, /accounts/{id}/public"),
			"shared_with": strArr("principals legitimately allowed: 'public' (everyone), 'authenticated' (any registered identity), 'unauthenticated', or specific role names (e.g. admin)"),
		},
		"required":             []any{"pattern", "shared_with"},
		"additionalProperties": false,
	}
	return writeTool("mobile_authz_expect",
		"Declare that an endpoint is LEGITIMATELY shared, so the authz verifier does not report expected access as IDOR/BOLA. Use for public endpoints, resources open to any authenticated user, or admin-accessible views. Matches the normalized route (ids as {id}). shared_with lists who may access it: 'public', 'authenticated', 'unauthenticated', or role names. Only matching principals are downgraded; genuine cross-identity disclosure elsewhere is still flagged. Register these before mobile_authz_sweep/mobile_authz_diff.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a authzExpectation
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if strings.TrimSpace(a.Pattern) == "" {
				return actool.Errorf("pattern is required"), nil
			}
			if len(a.SharedWith) == 0 {
				return actool.Errorf("shared_with is required (e.g. [\"authenticated\"] or [\"admin\"])"), nil
			}
			a.Method = strings.ToUpper(strings.TrimSpace(a.Method))
			addAuthzExpectation(t.taskID, a)
			out, _ := json.Marshal(map[string]any{"stored": true, "method": a.Method, "pattern": a.Pattern, "shared_with": a.SharedWith, "total": len(listAuthzExpectations(t.taskID))})
			return actool.Text(string(out)), nil
		})
}

func (t *ToolSet) mobileAuthzExpectList() actool.CoreTool {
	return readTool("mobile_authz_expect_list",
		"List the authorization expectations registered for this task (endpoints declared as legitimately shared, and who may access them).",
		obj(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			exps := listAuthzExpectations(t.taskID)
			sort.Slice(exps, func(i, j int) bool { return exps[i].Pattern < exps[j].Pattern })
			out, _ := json.Marshal(map[string]any{"count": len(exps), "expectations": exps})
			return actool.Text(string(out)), nil
		})
}
