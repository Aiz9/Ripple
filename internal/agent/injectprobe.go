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

// Injection probes (deterministically confirmable only). SSTI: inject an arithmetic
// expression in several template syntaxes and confirm the server returned the
// PRODUCT (the template engine evaluated it). Error-based SQLi: inject a quote and
// confirm a database error signature leaked. Both operate on a real captured
// request's parameters and confirm by evidence (evaluated value / DB error string),
// never by status code. Blind/time-based and OOB (SSRF) variants are intentionally
// out of scope here because they are not deterministically confirmable without
// timing models or an out-of-band collaborator.

// Distinct factors so the product can't appear by coincidence.
const sstiA, sstiB = 1009, 1013

func sstiProduct() string { return strconv.Itoa(sstiA * sstiB) } // 1022117

// sstiPayloads covers the common template syntaxes; each evaluates to sstiA*sstiB.
func sstiPayloads() []string {
	expr := strconv.Itoa(sstiA) + "*" + strconv.Itoa(sstiB)
	return []string{
		"{{" + expr + "}}",    // Jinja2 / Twig / Nunjucks
		"${" + expr + "}",     // JSP EL / Spring / FreeMarker / Thymeleaf
		"#{" + expr + "}",     // Ruby / JSF
		"<%= " + expr + " %>", // ERB
		"{" + expr + "}",      // some lightweight engines
	}
}

// detectSSTI reports whether the response shows the expression was evaluated.
func detectSSTI(responseBody string) bool {
	return strings.Contains(responseBody, sstiProduct())
}

// sqlErrorRe matches database error signatures that leak on a broken SQL string.
var sqlErrorRe = regexp.MustCompile(`(?i)(you have an error in your sql syntax|unterminated quoted string|unclosed quotation mark|sqlstate\[|ora-[0-9]{4,5}|psql:|pg::|sqlite(?:3)?(?:\.|::|exception)|mysql_fetch|supplied argument is not a valid mysql|org\.postgresql\.util\.psqlexception|microsoft odbc|odbc sql server driver|syntax error at or near|quoted string not properly terminated)`)

// detectSQLError reports whether a response leaks a DB error (error-based SQLi).
func detectSQLError(responseBody string) bool {
	return sqlErrorRe.MatchString(responseBody)
}

var sqlPayloads = []string{`'`, `"`, `')`, `' OR '1'='1`}

// injectTarget names one place a payload can go.
type injectTarget struct {
	Location string // "query" | "body"
	Name     string
}

// injectableTargets lists the string-valued query and JSON-body params of a request.
func injectableTargets(rawRequest string) []injectTarget {
	var out []injectTarget
	seen := map[string]bool{}
	add := func(loc, name string) {
		k := loc + "\x00" + name
		if name == "" || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, injectTarget{loc, name})
	}
	nl := strings.IndexAny(rawRequest, "\r\n")
	line := rawRequest
	if nl >= 0 {
		line = rawRequest[:nl]
	}
	if f := strings.Fields(line); len(f) >= 2 {
		if i := strings.IndexByte(f[1], '?'); i >= 0 {
			if vals, err := url.ParseQuery(f[1][i+1:]); err == nil {
				for k := range vals {
					add("query", k)
				}
			}
		}
	}
	if b := strings.TrimSpace(httpBody(rawRequest)); strings.HasPrefix(b, "{") {
		var m map[string]json.RawMessage
		if json.Unmarshal([]byte(b), &m) == nil {
			for k, v := range m {
				if strings.HasPrefix(strings.TrimSpace(string(v)), `"`) { // string field
					add("body", k)
				}
			}
		}
	}
	return out
}

// setQueryValue rewrites one query parameter's value in a raw request's request-line.
func setQueryValue(rawRequest, key, value string) (string, bool) {
	nl := strings.Index(rawRequest, "\r\n")
	if nl < 0 {
		return "", false
	}
	line, rest := rawRequest[:nl], rawRequest[nl:]
	f := strings.SplitN(line, " ", 3)
	if len(f) < 3 {
		return "", false
	}
	target := f[1]
	i := strings.IndexByte(target, '?')
	if i < 0 {
		return "", false
	}
	path, qs := target[:i], target[i+1:]
	vals, err := url.ParseQuery(qs)
	if err != nil {
		return "", false
	}
	if _, ok := vals[key]; !ok {
		return "", false
	}
	vals.Set(key, value)
	return f[0] + " " + path + "?" + vals.Encode() + " " + f[2] + rest, true
}

// injectInto returns a raw request with payload placed at target.
func injectInto(rawRequest string, target injectTarget, payload string) (string, bool) {
	switch target.Location {
	case "query":
		return setQueryValue(rawRequest, target.Name, payload)
	case "body":
		nb, ok := setJSONField(httpBody(rawRequest), target.Name, strconv.Quote(payload))
		if !ok {
			return "", false
		}
		return setRequestBody(rawRequest, nb), true
	}
	return "", false
}

func (t *ToolSet) mobileInjectProbe() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":       strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"history_index": intField("history index of a captured request whose params (query or JSON body strings) to test"),
		},
		"required":             []any{"history_index"},
		"additionalProperties": false,
	}
	return writeTool("mobile_inject_probe",
		"Deterministic injection probe for one captured request. For each string parameter (query/JSON body) it tests SSTI (injects an arithmetic expression in several template syntaxes; confirmed when the response returns the evaluated product) and error-based SQLi (injects a quote; confirmed when a database error signature leaks). Confirms by evidence, never by status code. Does not do blind/time-based or OOB (SSRF) — those need timing/collaborator infrastructure. SANDBOX ONLY.",
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
			targets := injectableTargets(req.Request)
			if len(targets) == 0 {
				return actool.Errorf("no injectable string parameters (query or JSON body) in the captured request"), nil
			}
			port := 443
			if !req.TLS {
				port = 80
			}
			send := func(raw string) string {
				resp, e := c.SendRequest(ctx, req.Host, port, req.TLS, raw)
				if e != nil {
					return ""
				}
				return resp
			}

			type hit struct {
				Param   string `json:"param"`
				Loc     string `json:"location"`
				Class   string `json:"class"`
				Payload string `json:"payload"`
			}
			var hits []hit
			tested := 0
			for _, tgt := range targets {
				// SSTI
				for _, p := range sstiPayloads() {
					if raw, ok := injectInto(req.Request, tgt, p); ok {
						tested++
						if detectSSTI(httpBody(send(raw))) {
							hits = append(hits, hit{tgt.Name, tgt.Location, "SSTI", p})
							break
						}
					}
				}
				// error-based SQLi
				for _, p := range sqlPayloads {
					if raw, ok := injectInto(req.Request, tgt, p); ok {
						tested++
						if detectSQLError(httpBody(send(raw))) {
							hits = append(hits, hit{tgt.Name, tgt.Location, "SQLi (error-based)", p})
							break
						}
					}
				}
			}

			result := map[string]any{
				"endpoint":      req.Method + " " + req.Host + req.Path,
				"params_tested": len(targets),
				"payloads_sent": tested,
				"confirmed":     hits,
				"note":          "SSTI confirmed by the evaluated product in the response; SQLi by a leaked DB error signature. Neither is inferred from status code.",
			}
			if len(hits) > 0 {
				var lines []string
				class := "Injection"
				for _, h := range hits {
					lines = append(lines, h.Class+" in "+h.Loc+" param '"+h.Param+"' (payload "+h.Payload+")")
					if h.Class != "Injection" {
						class = h.Class
					}
				}
				fb := &findingBlock{
					VulnClass:          class,
					Name:               "Injection on " + req.Method + " " + req.Path,
					Severity:           "critical",
					Summary:            "A request parameter is injectable: the server evaluated a template expression and/or leaked a database error, proving unsanitized input reaches an interpreter.",
					AffectedEndpoint:   req.Host + req.Path,
					Method:             req.Method,
					Preconditions:      "A captured request with the parameter(s) below (authorized sandbox).",
					Reproduction:       append([]string{"Replay " + req.Method + " " + req.Path + " with the payloads below:"}, lines...),
					Expected:           "Input is treated as data: no expression evaluation, no database error leakage.",
					Actual:             strings.Join(lines, "; "),
					Impact:             "Server-side code/template execution (SSTI → RCE) or database compromise (SQLi) via unsanitized parameters.",
					Remediation:        "Never pass user input into templates or SQL as code: use sandboxed/logic-less templates and parameterized queries / prepared statements; validate and encode input.",
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
