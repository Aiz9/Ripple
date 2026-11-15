package agent

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/internal/db"
	"github.com/Autumn-27/artex/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// Systematic API discovery from captured traffic.
//
// Endpoint discovery used to depend on the model deciding to call insertAssets
// after reading history by eye, so the inventory was whatever it happened to log.
// This harvester walks Burp proxy history deterministically, normalizes each
// request into a canonical route template (concrete object IDs collapsed to
// placeholders so /accounts/100345 and /accounts/100346 become one endpoint),
// extracts its parameters, and upserts the deduped set into the existing assets
// inventory. Everything it records is OBSERVED (seen in real traffic) — inferred
// and hypothesised endpoints come from other sources and are tracked separately.

// normalizePath collapses resource-identifier path segments into typed
// placeholders, yielding a stable route template for dedup. Returns the template
// and whether any segment was parameterized.
func normalizePath(path string) (string, bool) {
	if path == "" || path == "/" {
		return "/", false
	}
	segs := strings.Split(path, "/")
	param := false
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		dec := seg
		if d, err := url.PathUnescape(seg); err == nil {
			dec = d
		}
		if !isResourceID(dec) {
			continue
		}
		param = true
		// Single placeholder for every identifier shape: the same route must
		// collapse to one template whether the observed ID was numeric, a UUID, or
		// an opaque handle — distinct placeholders fragment the inventory.
		segs[i] = "{id}"
	}
	return strings.Join(segs, "/"), param
}

// requestParams extracts the parameter inventory of a raw request: query-string
// keys and, when the body is a JSON object, its top-level keys. Values are NOT
// recorded (they are per-instance and may be sensitive) — only name+location.
func requestParams(rawRequest string) []map[string]any {
	seen := map[string]bool{}
	var out []map[string]any
	add := func(loc, name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		key := loc + "\x00" + name
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, map[string]any{"location": loc, "name": name})
	}

	nl := strings.IndexAny(rawRequest, "\r\n")
	line := rawRequest
	if nl >= 0 {
		line = rawRequest[:nl]
	}
	if f := strings.Fields(line); len(f) >= 2 {
		target := f[1]
		if i := strings.IndexByte(target, '?'); i >= 0 {
			if vals, err := url.ParseQuery(target[i+1:]); err == nil {
				for k := range vals {
					add("query", k)
				}
			}
		}
	}

	body := httpBody(rawRequest)
	if b := strings.TrimSpace(body); strings.HasPrefix(b, "{") {
		var obj map[string]json.RawMessage
		if json.Unmarshal([]byte(b), &obj) == nil {
			for k := range obj {
				add("body", k)
			}
		}
	}
	return out
}

// requestHasAuth reports whether the raw request carried an auth-bearing header.
func requestHasAuth(rawRequest string) bool {
	head := rawRequest
	if i := strings.Index(rawRequest, "\r\n\r\n"); i >= 0 {
		head = rawRequest[:i]
	}
	for _, ln := range strings.Split(head, "\n") {
		name, _, ok := strings.Cut(strings.TrimRight(ln, "\r"), ":")
		if !ok {
			continue
		}
		lname := strings.ToLower(strings.TrimSpace(name))
		for _, a := range authHeaderNames {
			if lname == a {
				return true
			}
		}
	}
	return false
}

// endpointKey identifies a unique normalized endpoint.
type endpointKey struct{ method, url string }

type endpointAgg struct {
	method, url string
	params      []map[string]any
	paramSeen   map[string]bool
	count       int
	authSeen    bool
}

// exchangeEndpoint derives (method, canonical URL template) from one exchange.
// scheme defaults to https (mobile apps are overwhelmingly TLS) when the request
// is origin-form and history carries no TLS flag. shortcut: assumes https for
// origin-form requests; upgrade if plaintext endpoints must be distinguished.
func exchangeEndpoint(ex devicelab.Exchange) (method, canonURL string, ok bool) {
	method = strings.ToUpper(ex.Method)
	if method == "" {
		return "", "", false
	}
	host := ex.Host
	scheme := "https"
	rawPath := ex.Path
	if strings.Contains(ex.Path, "://") {
		if u, err := url.Parse(ex.Path); err == nil {
			scheme = u.Scheme
			if u.Host != "" {
				host = u.Host
			}
			rawPath = u.Path
		}
	} else if i := strings.IndexByte(ex.Path, '?'); i >= 0 {
		rawPath = ex.Path[:i]
	}
	if host == "" {
		return "", "", false
	}
	tmpl, _ := normalizePath(rawPath)
	return method, scheme + "://" + host + tmpl, true
}

func (t *ToolSet) mobileAPIHarvest() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url": strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"offset":  intField("history offset to start from (default 0)"),
			"count":   intField("max exchanges to scan (default 500)"),
		},
		"additionalProperties": false,
	}
	return writeTool("mobile_api_harvest",
		"Systematically build the API inventory from captured traffic. Walks Burp proxy history, normalizes every request into a canonical route template (concrete object IDs collapsed to {id} so repeated calls dedupe into one endpoint), extracts its query/body parameters and whether it required auth, and upserts the deduped set of OBSERVED endpoints into the assets inventory. Run this after driving the app so discovery is complete and reproducible instead of relying on ad-hoc insert_assets calls. Returns the endpoints discovered with observed counts.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("asset store unavailable in this context"), nil
			}
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

			aggs := map[endpointKey]*endpointAgg{}
			for _, ex := range hist {
				method, canonURL, ok := exchangeEndpoint(ex)
				if !ok {
					continue
				}
				k := endpointKey{method, canonURL}
				ag := aggs[k]
				if ag == nil {
					ag = &endpointAgg{method: method, url: canonURL, paramSeen: map[string]bool{}}
					aggs[k] = ag
				}
				ag.count++
				if requestHasAuth(ex.Request) {
					ag.authSeen = true
				}
				for _, p := range requestParams(ex.Request) {
					pk := p["location"].(string) + "\x00" + p["name"].(string)
					if !ag.paramSeen[pk] {
						ag.paramSeen[pk] = true
						ag.params = append(ag.params, p)
					}
				}
			}

			type row struct {
				Method        string `json:"method"`
				URL           string `json:"url"`
				ObservedCount int    `json:"observed_count"`
				AuthRequired  bool   `json:"auth_required"`
				Params        int    `json:"params"`
				Stored        bool   `json:"stored"`
				Err           string `json:"error,omitempty"`
			}
			rows := make([]row, 0, len(aggs))
			stored := 0
			for _, ag := range aggs {
				r := row{Method: ag.method, URL: ag.url, ObservedCount: ag.count, AuthRequired: ag.authSeen, Params: len(ag.params)}
				_, uerr := t.as.UpsertEndpoint(db.UpsertEndpointReq{URL: ag.url, Method: ag.method, Params: ag.params, TaskID: t.taskID})
				if uerr != nil {
					r.Err = uerr.Error()
				} else {
					r.Stored = true
					stored++
					t.writes.Assets++
				}
				rows = append(rows, r)
			}
			sort.Slice(rows, func(i, j int) bool {
				if rows[i].URL != rows[j].URL {
					return rows[i].URL < rows[j].URL
				}
				return rows[i].Method < rows[j].Method
			})
			out, _ := json.Marshal(map[string]any{
				"exchanges_scanned": len(hist),
				"unique_endpoints":  len(rows),
				"stored":            stored,
				"source":            "observed",
				"endpoints":         rows,
			})
			return actool.Text(string(out)), nil
		})
}
