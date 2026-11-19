package agent

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	actool "github.com/Autumn-27/norma/tool"
)

// Identity is a controlled test account used for authorization testing (IDOR/BOLA
// and business-logic flaws): its auth material is swapped into a captured request
// so the same request can be replayed as a different principal. Values are
// test-account secrets held in memory only — never logged, never persisted — and
// scoped to one task so engagements do not leak into each other.
type Identity struct {
	Role    string            `json:"role"`              // stable key: "user_a", "user_b", "admin"
	Label   string            `json:"label,omitempty"`   // human note, e.g. "owns account A / beneficiary A"
	Headers map[string]string `json:"headers,omitempty"` // auth headers to apply (Authorization, Cookie, X-Api-Key…)
	Owns    []string          `json:"owns,omitempty"`    // object ids this identity legitimately owns (explicit ownership map)
}

// ownershipMap returns role -> owned object ids for a task (the explicit ownership
// model, as opposed to inferring ownership from which token captured a request).
func ownershipMap(taskID int64) map[string][]string {
	identityMu.Lock()
	defer identityMu.Unlock()
	out := map[string][]string{}
	for role, id := range identityStore[taskID] {
		if len(id.Owns) > 0 {
			out[role] = id.Owns
		}
	}
	return out
}

// ownerOfID returns the role that owns a given object id, or "" if unknown.
func ownerOfID(taskID int64, id string) string {
	identityMu.Lock()
	defer identityMu.Unlock()
	for role, ident := range identityStore[taskID] {
		for _, o := range ident.Owns {
			if o == id {
				return role
			}
		}
	}
	return ""
}

var (
	identityMu    sync.Mutex
	identityStore = map[int64]map[string]Identity{} // taskID -> role -> identity
)

func setIdentity(taskID int64, id Identity) {
	identityMu.Lock()
	defer identityMu.Unlock()
	if identityStore[taskID] == nil {
		identityStore[taskID] = map[string]Identity{}
	}
	identityStore[taskID][id.Role] = id
}

func getIdentity(taskID int64, role string) (Identity, bool) {
	identityMu.Lock()
	defer identityMu.Unlock()
	id, ok := identityStore[taskID][role]
	return id, ok
}

func listIdentities(taskID int64) []Identity {
	identityMu.Lock()
	defer identityMu.Unlock()
	out := make([]Identity, 0, len(identityStore[taskID]))
	for _, id := range identityStore[taskID] {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Role < out[j].Role })
	return out
}

// redactHeaderKeys returns the header names only, so a listing never echoes token
// values back into the transcript.
func redactHeaderKeys(h map[string]string) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// extractAuthHeaders pulls the common authentication headers out of a raw HTTP/1.1
// request so an identity can be registered straight from a captured request.
func extractAuthHeaders(raw string) map[string]string {
	out := map[string]string{}
	head := raw
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		head = raw[:i]
	} else if i := strings.Index(raw, "\n\n"); i >= 0 {
		head = raw[:i]
	}
	for _, line := range strings.Split(head, "\n") {
		line = strings.TrimRight(line, "\r")
		name, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "authorization", "cookie", "x-api-key", "x-auth-token", "x-access-token":
			out[strings.TrimSpace(name)] = strings.TrimSpace(val)
		}
	}
	return out
}

// applyIdentityHeaders rewrites a raw HTTP/1.1 request so the given headers take
// effect (existing header lines of the same name, case-insensitively, are
// replaced; new ones are appended). The request line and body are preserved. This
// is the IDOR/BOLA primitive: swap identity A's request to carry identity B's auth.
func applyIdentityHeaders(raw string, headers map[string]string) string {
	if len(headers) == 0 {
		return raw
	}
	head, body := raw, ""
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		head, body = raw[:i], raw[i:] // body keeps its leading CRLFCRLF
	} else if i := strings.Index(raw, "\n\n"); i >= 0 {
		head, body = raw[:i], "\r\n\r\n"+raw[i+2:]
	}
	lines := strings.Split(head, "\n")
	drop := map[string]bool{}
	for k := range headers {
		drop[strings.ToLower(k)] = true
	}
	kept := make([]string, 0, len(lines))
	for i, line := range lines {
		l := strings.TrimRight(line, "\r")
		if i == 0 { // request line
			kept = append(kept, l)
			continue
		}
		if name, _, ok := strings.Cut(l, ":"); ok && drop[strings.ToLower(strings.TrimSpace(name))] {
			continue // replaced below
		}
		kept = append(kept, l)
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names) // deterministic output
	for _, k := range names {
		kept = append(kept, k+": "+headers[k])
	}
	if body == "" {
		body = "\r\n\r\n"
	}
	return strings.Join(kept, "\r\n") + body
}

func (t *ToolSet) mobileIdentitySet() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"role":         strField("stable identity key, e.g. user_a, user_b, admin"),
			"label":        strField("human note, e.g. 'owns account A / beneficiary A'"),
			"headers":      map[string]any{"type": "object", "description": "auth headers to swap in when replaying as this identity (e.g. {\"Authorization\":\"Bearer …\",\"Cookie\":\"session=…\"})", "additionalProperties": map[string]any{"type": "string"}},
			"from_request": strField("optional raw HTTP request captured as this identity; Authorization/Cookie/X-Api-Key/X-Auth-Token/X-Access-Token are extracted from it"),
			"owns":         strArr("object ids this identity legitimately owns (e.g. account/beneficiary/transaction ids) — the explicit ownership map used to prove cross-owner access"),
		},
		"required":             []any{"role"},
		"additionalProperties": false,
	}
	return writeTool("mobile_identity_set",
		"Register (or update) a controlled test identity for authorization testing (IDOR/BOLA, business-logic). Provide its auth material via `headers` and/or `from_request`; it is stored for THIS task only and swapped into captured requests by mobile_traffic_replay (as_role). Register at least two owners (e.g. user_a owning account A, user_b owning account B) plus admin to test object- and function-level authorization. The stored token is STATIC: on single-session targets (one login invalidates the previous token, so the two accounts evict each other) log each account in with a DISTINCT device/registration id, and re-call this to refresh a role's token right before replaying as it. Values are not logged or echoed back.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Role        string            `json:"role"`
				Label       string            `json:"label"`
				Headers     map[string]string `json:"headers"`
				FromRequest string            `json:"from_request"`
				Owns        []string          `json:"owns"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if strings.TrimSpace(a.Role) == "" {
				return actool.Errorf("role is required"), nil
			}
			headers := map[string]string{}
			for k, v := range extractAuthHeaders(a.FromRequest) {
				headers[k] = v
			}
			for k, v := range a.Headers { // explicit headers override extracted ones
				if strings.TrimSpace(k) != "" {
					headers[k] = v
				}
			}
			if len(headers) == 0 {
				return actool.Errorf("no auth headers given; provide `headers` or a `from_request` containing Authorization/Cookie/X-Api-Key"), nil
			}
			setIdentity(t.taskID, Identity{Role: strings.TrimSpace(a.Role), Label: strings.TrimSpace(a.Label), Headers: headers, Owns: a.Owns})
			out, _ := json.Marshal(map[string]any{"role": strings.TrimSpace(a.Role), "header_keys": redactHeaderKeys(headers), "owns": a.Owns, "stored": true})
			return actool.Text(string(out)), nil
		})
}

func (t *ToolSet) mobileIdentityList() actool.CoreTool {
	return readTool("mobile_identity_list",
		"List the controlled test identities registered for this task (role, label, and which auth header names are set — values are redacted). Use these roles with mobile_traffic_replay's as_role to replay a captured request as a different principal.",
		obj(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			ids := listIdentities(t.taskID)
			type row struct {
				Role       string   `json:"role"`
				Label      string   `json:"label,omitempty"`
				HeaderKeys []string `json:"header_keys"`
				Owns       []string `json:"owns,omitempty"`
			}
			rows := make([]row, 0, len(ids))
			for _, id := range ids {
				rows = append(rows, row{Role: id.Role, Label: id.Label, HeaderKeys: redactHeaderKeys(id.Headers), Owns: id.Owns})
			}
			out, _ := json.Marshal(map[string]any{"count": len(rows), "identities": rows})
			return actool.Text(string(out)), nil
		})
}
