package agent

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// OpenAPI / Swagger ingestion. A spec documents endpoints that may never have been
// observed in traffic; these are INFERRED, not confirmed — a documented route is a
// hypothesis until a request to it is actually seen. This parses Swagger v2 and
// OpenAPI v3 into normalized endpoints (source=spec), kept as a distinct inferred
// layer so the agent can (a) know what to exercise and (b) diff against the
// observed inventory to surface documented-but-untested and undocumented (shadow)
// endpoints. It never promotes a spec entry to an observed/confirmed endpoint.

var pathParamRe = regexp.MustCompile(`\{[^}]+\}`)

type specEndpoint struct {
	Method       string           `json:"method"`
	Path         string           `json:"path"` // normalized: all path params -> {id}
	OperationID  string           `json:"operation_id,omitempty"`
	AuthRequired bool             `json:"auth_required"`
	Params       []map[string]any `json:"params,omitempty"`
}

// normalizeSpecPath lowercases nothing but replaces every {param} template segment
// with {id} so a spec path matches the observed-inventory convention.
func normalizeSpecPath(p string) string {
	return pathParamRe.ReplaceAllString(p, "{id}")
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func specBasePath(doc map[string]any) string {
	if bp, ok := doc["basePath"].(string); ok && bp != "" { // Swagger v2
		return strings.TrimRight(bp, "/")
	}
	if servers, ok := doc["servers"].([]any); ok && len(servers) > 0 { // OpenAPI v3
		if s := asMap(servers[0]); s != nil {
			if u, ok := s["url"].(string); ok {
				if parsed, err := url.Parse(u); err == nil && parsed.Path != "/" {
					return strings.TrimRight(parsed.Path, "/")
				}
			}
		}
	}
	return ""
}

var httpMethods = map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "head": true, "options": true}

// collectParams extracts {location,name} from a parameters array plus a v3
// requestBody / v2 body-schema (as location=body).
func collectParams(params []any, op map[string]any) []map[string]any {
	seen := map[string]bool{}
	var out []map[string]any
	add := func(loc, name string) {
		name = strings.TrimSpace(name)
		if name == "" || loc == "" {
			return
		}
		k := loc + "\x00" + name
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, map[string]any{"location": loc, "name": name})
	}
	for _, p := range params {
		pm := asMap(p)
		in, _ := pm["in"].(string)
		name, _ := pm["name"].(string)
		switch in {
		case "query", "path", "header", "cookie":
			add(in, name)
		case "body": // Swagger v2 body parameter
			if sc := asMap(pm["schema"]); sc != nil {
				for k := range asMap(sc["properties"]) {
					add("body", k)
				}
			}
		}
	}
	// OpenAPI v3 requestBody
	if rb := asMap(op["requestBody"]); rb != nil {
		for _, ct := range asMap(rb["content"]) {
			if sc := asMap(asMap(ct)["schema"]); sc != nil {
				for k := range asMap(sc["properties"]) {
					add("body", k)
				}
			}
		}
	}
	return out
}

// hasAuth reports whether an operation requires auth: a non-empty operation-level
// security list, or (when absent) a non-empty global security list.
func hasAuth(op map[string]any, globalSecurity []any) bool {
	if sec, ok := op["security"].([]any); ok {
		return len(sec) > 0
	}
	return len(globalSecurity) > 0
}

// parseOpenAPI parses a Swagger v2 / OpenAPI v3 document into normalized endpoints.
func parseOpenAPI(spec []byte) ([]specEndpoint, error) {
	var doc map[string]any
	if err := json.Unmarshal(spec, &doc); err != nil {
		return nil, err
	}
	base := specBasePath(doc)
	global, _ := doc["security"].([]any)
	paths := asMap(doc["paths"])
	var out []specEndpoint
	for rawPath, pi := range paths {
		item := asMap(pi)
		if item == nil {
			continue
		}
		var pathParams []any
		if pp, ok := item["parameters"].([]any); ok {
			pathParams = pp
		}
		norm := normalizeSpecPath(base + rawPath)
		for method, opv := range item {
			if !httpMethods[strings.ToLower(method)] {
				continue
			}
			op := asMap(opv)
			if op == nil {
				continue
			}
			var opParams []any
			if p, ok := op["parameters"].([]any); ok {
				opParams = p
			}
			combined := append(append([]any{}, pathParams...), opParams...)
			oid, _ := op["operationId"].(string)
			out = append(out, specEndpoint{
				Method:       strings.ToUpper(method),
				Path:         norm,
				OperationID:  oid,
				AuthRequired: hasAuth(op, global),
				Params:       collectParams(combined, op),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out, nil
}

func (t *ToolSet) mobileOpenAPIIngest() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"spec": strField("the OpenAPI v3 or Swagger v2 document as JSON (e.g. an api-docs/swagger.json found in the app or its backend)"),
		},
		"required":             []any{"spec"},
		"additionalProperties": false,
	}
	return readTool("mobile_openapi_ingest",
		"Ingest an OpenAPI v3 / Swagger v2 spec into the INFERRED endpoint layer (source=spec): normalized method+path (params as {id}), parameters and auth requirement. These are documented hypotheses, NOT confirmed endpoints — exercise them to produce real traffic (then mobile_api_harvest records the observed ones), and diff documented-but-unobserved vs observed-but-undocumented (shadow) endpoints. Does not alter the observed inventory.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Spec string `json:"spec"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if strings.TrimSpace(a.Spec) == "" {
				return actool.Errorf("spec is required (OpenAPI v3 or Swagger v2 JSON)"), nil
			}
			eps, err := parseOpenAPI([]byte(a.Spec))
			if err != nil {
				return errf("parse spec: %v", err), nil
			}
			if len(eps) == 0 {
				return actool.Errorf("no paths found; is this an OpenAPI/Swagger document?"), nil
			}
			out, _ := json.Marshal(map[string]any{
				"source":              "spec",
				"verification_status": "inferred",
				"count":               len(eps),
				"endpoints":           eps,
				"note":                "inferred endpoints are documented hypotheses; confirm by driving traffic, then harvest. Compare with the observed inventory to find untested and undocumented (shadow) endpoints.",
			})
			return actool.Text(string(out)), nil
		})
}
