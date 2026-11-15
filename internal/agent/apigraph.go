package agent

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/internal/devicelab"
	actool "github.com/Autumn-27/norma/tool"
)

// API relationship & dependency graph. Beyond a flat endpoint list, the engine
// needs the interconnected model: which object each endpoint acts on, and which
// endpoint PRODUCES an identifier that another endpoint CONSUMES (so a flow can be
// chained, and BOLA targets — endpoints that take an object id — are known with
// their id's origin). Built deterministically from captured traffic: produced ids
// come from response bodies, consumed ids from request path/query/body, and an
// edge P→C is drawn when C uses a value P emitted earlier.

// idKeyRe marks JSON keys that name identifiers (so amounts, balances, counts etc.
// do not create spurious edges). It deliberately avoids a bare "id$" so plain words
// ending in "id" (valid, paid, void) are not matched; camelCase "...Id" is handled
// separately in idLikeKey.
var idKeyRe = regexp.MustCompile(`(?i)(^id$|_id$|uuid|guid|reference|^ref$|account|txn|transaction|order|invoice|number|identifier)`)

func idLikeKey(key string) bool {
	return idKeyRe.MatchString(key) || strings.HasSuffix(key, "Id") || strings.HasSuffix(key, "ID")
}

// idLikeValue reports whether a JSON leaf (key,value) is an identifier worth
// tracking. Strings count when id-shaped OR under an id-like key; numbers only
// under an id-like key (avoids treating amounts as ids).
func idLikeValue(key string, v any) (string, bool) {
	switch t := v.(type) {
	case string:
		if isResourceID(t) || idLikeKey(key) {
			if strings.TrimSpace(t) != "" {
				return t, true
			}
		}
	case float64:
		if t == float64(int64(t)) && (t >= 10 || t <= -10) && idLikeKey(key) {
			return strconv.FormatInt(int64(t), 10), true
		}
	case json.Number:
		if idLikeKey(key) {
			return t.String(), true
		}
	}
	return "", false
}

// collectJSONIDs walks a JSON body and returns the set of identifier-like leaf
// values it contains.
func collectJSONIDs(body string) map[string]bool {
	out := map[string]bool{}
	var v any
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &v) != nil {
		return out
	}
	var walk func(key string, val any)
	walk = func(key string, val any) {
		switch t := val.(type) {
		case map[string]any:
			for k, vv := range t {
				walk(k, vv)
			}
		case []any:
			for _, vv := range t {
				walk(key, vv)
			}
		default:
			if id, ok := idLikeValue(key, val); ok {
				out[id] = true
			}
		}
	}
	walk("", v)
	return out
}

// producedIDs are the identifier-like values in a response body.
func producedIDs(responseRaw string) map[string]bool {
	return collectJSONIDs(httpBody(responseRaw))
}

// consumedIDs are the identifier-like values a request carries, from path/query
// (resourceIDs) and its JSON body.
func consumedIDs(requestRaw string) map[string]bool {
	out := map[string]bool{}
	for _, id := range resourceIDs(requestRaw) {
		out[id] = true
	}
	for id := range collectJSONIDs(httpBody(requestRaw)) {
		out[id] = true
	}
	return out
}

// objectName is the resource an endpoint acts on: the last non-placeholder path
// segment (e.g. /accounts/{id}/beneficiaries -> "beneficiaries").
func objectName(pathTemplate string) string {
	segs := strings.Split(pathTemplate, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		s := segs[i]
		if s == "" || strings.HasPrefix(s, "{") {
			continue
		}
		return s
	}
	return "/"
}

type graphEdge struct {
	From string `json:"from"` // producer endpoint "METHOD path"
	To   string `json:"to"`   // consumer endpoint
	Via  string `json:"via"`  // the identifier value linking them
}

type graphNode struct {
	Endpoint string   `json:"endpoint"` // "METHOD path"
	Object   string   `json:"object"`
	Consumes []string `json:"consumes,omitempty"` // id values it takes as input
	Produces []string `json:"produces,omitempty"` // id values seen in its response
}

// buildAPIGraph derives endpoints (with object + produced/consumed ids) and
// producer→consumer dependency edges from captured exchanges, in observation order.
func buildAPIGraph(hist []devicelab.Exchange) ([]graphNode, []graphEdge) {
	type agg struct {
		object   string
		consumes map[string]bool
		produces map[string]bool
	}
	nodes := map[string]*agg{}
	var nodeOrder []string
	firstProducer := map[string]string{} // id value -> endpoint that first produced it
	edgeSeen := map[string]bool{}
	var edges []graphEdge

	label := func(method, canon string) string { return method + " " + pathOf(canon) }

	for _, ex := range hist {
		method, canon, ok := exchangeEndpoint(ex)
		if !ok {
			continue
		}
		ep := label(method, canon)
		n := nodes[ep]
		if n == nil {
			n = &agg{object: objectName(pathOf(canon)), consumes: map[string]bool{}, produces: map[string]bool{}}
			nodes[ep] = n
			nodeOrder = append(nodeOrder, ep)
		}
		cons := consumedIDs(ex.Request)
		for id := range cons {
			n.consumes[id] = true
			if p, ok := firstProducer[id]; ok && p != ep {
				k := p + "\x00" + ep + "\x00" + id
				if !edgeSeen[k] {
					edgeSeen[k] = true
					edges = append(edges, graphEdge{From: p, To: ep, Via: id})
				}
			}
		}
		prod := producedIDs(ex.Response)
		for id := range prod {
			n.produces[id] = true
			if _, ok := firstProducer[id]; !ok {
				firstProducer[id] = ep
			}
		}
	}

	setToSorted := func(m map[string]bool) []string {
		s := make([]string, 0, len(m))
		for k := range m {
			s = append(s, k)
		}
		sort.Strings(s)
		return s
	}
	out := make([]graphNode, 0, len(nodeOrder))
	for _, ep := range nodeOrder {
		n := nodes[ep]
		out = append(out, graphNode{Endpoint: ep, Object: n.object, Consumes: setToSorted(n.consumes), Produces: setToSorted(n.produces)})
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})
	return out, edges
}

func (t *ToolSet) mobileAPIGraph() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url": strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"offset":  intField("history offset (default 0)"),
			"count":   intField("max exchanges to scan (default 500)"),
		},
		"additionalProperties": false,
	}
	return readTool("mobile_api_graph",
		"Build the API relationship & dependency graph from captured traffic: each endpoint with the object it acts on and the identifier values it consumes (input) and produces (in its response), plus producer→consumer edges (endpoint A emits an id that endpoint B then uses). Use it to chain multi-step flows and to target authorization testing — endpoints that consume object ids produced elsewhere are prime BOLA candidates. Derived deterministically from history; run after harvesting traffic.",
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
			nodes, edges := buildAPIGraph(hist)
			objects := map[string][]string{}
			for _, n := range nodes {
				objects[n.Object] = append(objects[n.Object], n.Endpoint)
			}
			out, _ := json.Marshal(map[string]any{
				"endpoints_scanned": len(hist),
				"objects":           objects,
				"nodes":             nodes,
				"dependencies":      edges,
				"note":              "edges are producer→consumer by shared identifier value, in observed order; consumers of externally-produced ids are BOLA candidates.",
			})
			return actool.Text(string(out)), nil
		})
}
