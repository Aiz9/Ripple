package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/internal/db"
	actool "github.com/Autumn-27/norma/tool"
)

// assetInterceptCandidates extracts domain/IP/URL strings from pending asset input for rule matching.
// Extract and classify URL hosts so URL-only services/endpoints match domain/IP rules too.
func assetInterceptCandidates(item assetInputItem) (domains, ips, urls []string) {
	add := func(dst *[]string, s string) {
		if s = strings.TrimSpace(s); s != "" {
			*dst = append(*dst, s)
		}
	}
	add(&domains, item.Domain)
	for _, d := range item.BoundDomains {
		add(&domains, d)
	}
	add(&ips, item.IP)
	add(&ips, item.ServiceIP)
	add(&urls, item.URL)
	if item.URL != "" {
		if u, err := url.Parse(item.URL); err == nil {
			if h := u.Hostname(); h != "" {
				if net.ParseIP(h) != nil {
					add(&ips, h)
				} else {
					add(&domains, h)
				}
			}
		}
	}
	return domains, ips, urls
}

// assetInputLabel returns a compact pending-asset identifier for interception messages.
func assetInputLabel(item assetInputItem) string {
	typ := strings.TrimSpace(item.Type)
	var target string
	switch {
	case strings.TrimSpace(item.Domain) != "":
		target = strings.TrimSpace(item.Domain)
	case strings.TrimSpace(item.URL) != "":
		target = strings.TrimSpace(item.URL)
	case strings.TrimSpace(item.IP) != "":
		target = strings.TrimSpace(item.IP)
	case strings.TrimSpace(item.ServiceIP) != "":
		target = strings.TrimSpace(item.ServiceIP)
	default:
		target = "(unknown)"
	}
	if typ != "" {
		return fmt.Sprintf("[%s] %s", typ, target)
	}
	return target
}

// =====================================================================
// Unified asset insertion tools
// =====================================================================

// SetAssetStore wires the asset store and company store onto this ToolSet
// so the insert_assets, add_company_scope, and list_assets tools are active.
func (t *ToolSet) SetAssetStore(as *db.AssetStore, cs *db.CompanyStore) {
	t.as = as
	t.cs = cs
}

// assetInputItem is one element of the insert_assets "assets" array.
type assetInputItem struct {
	Type string `json:"type"` // root_domain|ip|subdomain|app|service|endpoint

	// ---- root_domain / subdomain ----
	Domain      string   `json:"domain"`
	ICP         string   `json:"icp"`
	RecordType  string   `json:"record_type"`
	RecordValue []string `json:"record_value"`

	// ---- ip ----
	IP           string           `json:"ip"`
	BoundDomains []string         `json:"bound_domains"`
	OpenPorts    []db.PortService `json:"open_ports"`

	// ---- app ----
	AppName     string `json:"app_name"`
	BundleID    string `json:"bundle_id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	AppICP      string `json:"app_icp"`
	CompanyID   *int64 `json:"company_id"` // explicit company link (app only; others auto-attribute via scope)

	// ---- service (http) ----
	URL           string           `json:"url"`
	Technologies  []string         `json:"technologies"`
	StatusCode    *int             `json:"status_code"`
	ContentLength *int64           `json:"content_length"`
	PageTitle     string           `json:"page_title"`
	FaviconMMH3   string           `json:"favicon_mmh3"`
	Auth          []map[string]any `json:"auth"`
	ServiceName   string           `json:"service_name"`
	ServiceIP     string           `json:"service_ip"` // optional enrichment IP

	// ---- service (other) ----
	Port  int    `json:"port"`
	Proto string `json:"proto"`

	// ---- endpoint ----
	Method string           `json:"method"`
	Params []map[string]any `json:"params"`
}

// insertAssets is the unified insert_assets agent tool.
func (t *ToolSet) insertAssets() actool.CoreTool {
	return writeTool(
		"insert_assets",
		"Register newly discovered assets in a batch; types may be mixed (see type enum).\n"+
			"Required fields by type: root_domain -> domain; ip -> ip (IPv4/IPv6, not a hostname); subdomain -> domain; app -> app_name; service(HTTP) -> url; service(non-HTTP) -> service_name+port and at least one of ip/domain; endpoint -> url+method. See individual field descriptions for other fields.\n"+
			"auth/technologies/params are appended and merged, preserving existing values.\n"+
			"Returns: {results:[{index,id,type}], errors:[{index,error}]}",
		obj(map[string]any{
			// Do not expose task_id to models; SetTaskID authoritatively assigns Worker ownership.
			"assets": map[string]any{
				"type":        "array",
				"description": "Asset array, one record per element",
				"items": obj(map[string]any{
					"type": map[string]any{
						"type":        "string",
						"enum":        []string{"root_domain", "ip", "subdomain", "app", "service", "endpoint"},
						"description": "Asset type",
					},
					// root_domain / subdomain
					"domain":      str("Root domain or subdomain (required for root_domain/subdomain)"),
					"icp":         str("Optional ICP registration number"),
					"record_type": str("Optional subdomain DNS record type: A/AAAA/CNAME/MX, etc."),
					"record_value": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Optional subdomain DNS values, for example [\"1.2.3.4\",\"2.3.4.5\"]",
					},
					// ip
					"ip": str("IPv4/IPv6 address, never a hostname (use subdomain.domain for hostnames). Required for ip; optional for service/endpoint to associate an IP"),
					"bound_domains": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Optional domains bound to an ip asset",
					},
					"open_ports": map[string]any{
						"type":        "array",
						"description": "Optional open ports for an ip asset",
						"items": obj(map[string]any{
							"port":    intp("Port number"),
							"service": str("Optional service name such as http/ssh/mysql"),
						}, "port"),
					},
					// app
					"app_name":    str("Application name (required for app)"),
					"bundle_id":   str("Optional app Bundle ID"),
					"category":    str("Optional application category"),
					"description": str("Optional application description"),
					"app_icp":     str("Optional application ICP registration"),
					"company_id":  intp("Optional owning company ID for app. App ownership cannot be inferred from scope and must be explicit. add_company_scope returns this ID"),
					// service (http)
					"url":         str("Full URL with scheme and port (required for HTTP service; service_type automatically becomes http)"),
					"status_code": intp("Optional HTTP response status such as 200/301/403/404"),
					"content_length": map[string]any{
						"type":        "integer",
						"description": "Optional HTTP response-body byte count",
					},
					"page_title":   str("Optional page <title> text"),
					"favicon_mmh3": str("Optional favicon MMH3 hash"),
					"technologies": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Optional fingerprints/technologies, for example [\"Nginx\",\"Vue\",\"Bootstrap\"]",
					},
					"auth": map[string]any{
						"type":        "array",
						"description": "Optional discovered authentication records with type/username/password, etc.; append without overwriting",
						"items":       map[string]any{"type": "object"},
					},
					// service (other, non-HTTP)
					"service_name": str("Service name such as ssh/mysql/redis (required for non-HTTP service)"),
					"port":         intp("Port number (required for non-HTTP service)"),
					// endpoint
					"method": str("HTTP method GET/POST/PUT/PATCH/DELETE, etc. (required for endpoint)"),
					"params": map[string]any{
						"type":        "array",
						"description": "Optional request parameters with location(query/body/header/path)/name/value/type; append without overwriting",
						"items":       map[string]any{"type": "object"},
					},
				}, "type"),
			},
		}, "assets"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("insert_assets disabled: AssetStore is not initialized"), nil
			}
			var a struct {
				Assets []assetInputItem `json:"assets"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			// Program-set task_id through SetTaskID prevents missing/wrong model values from losing or
			// misassigning task ownership. Auto/pentest/chat without task context use t.taskID=0.
			taskID := t.taskID

			type result struct {
				Index int    `json:"index"`
				ID    int64  `json:"id"`
				Type  string `json:"type"`
			}
			type errEntry struct {
				Index int    `json:"index"`
				Error string `json:"error"`
			}

			var results []result
			var errs []errEntry

			// Load gate rules once; read failure skips validation without blocking insertion.
			// Block rules combine global and task rules; allow rules belong to this task only.
			blockRules, _ := t.as.ListAssetInterceptRules()
			var allowRules []db.AssetInterceptRule
			if t.taskID > 0 {
				if tb, ta, err := t.as.TaskInterceptRulesSplit(t.taskID); err == nil {
					blockRules = append(blockRules, tb...)
					allowRules = ta
				}
			}

			for i, item := range a.Assets {
				// Apply block before allow; rejected assets skip Upsert and all subsequent side effects.
				domains, ips, urls := assetInterceptCandidates(item)
				if d := db.EvaluateAssetGate(blockRules, allowRules, domains, ips, urls); !d.Allowed {
					errs = append(errs, errEntry{
						Index: i,
						Error: fmt.Sprintf("Asset %s %s; insertion prohibited", assetInputLabel(item), d.Reason),
					})
					continue
				}

				typ := strings.TrimSpace(item.Type)
				var id int64
				var err error

				switch typ {
				case "root_domain":
					id, err = t.as.UpsertRootDomain(db.UpsertRootDomainReq{
						Domain: item.Domain,
						ICP:    item.ICP,
						TaskID: taskID,
					})

				case "ip":
					id, err = t.as.UpsertIP(db.UpsertIPReq{
						IP:           item.IP,
						BoundDomains: item.BoundDomains,
						OpenPorts:    item.OpenPorts,
						TaskID:       taskID,
					})

				case "subdomain":
					id, err = t.as.UpsertSubdomain(db.UpsertSubdomainReq{
						Domain:      item.Domain,
						RecordType:  item.RecordType,
						RecordValue: item.RecordValue,
						ICP:         item.ICP,
						TaskID:      taskID,
					})

				case "app":
					id, err = t.as.UpsertApp(db.UpsertAppReq{
						Name:        item.AppName,
						BundleID:    item.BundleID,
						Category:    item.Category,
						Description: item.Description,
						ICP:         item.AppICP,
						CompanyID:   item.CompanyID,
						TaskID:      taskID,
					})

				case "service":
					// distinguish HTTP vs other by presence of url
					if item.URL != "" {
						// agent may send "ip" or "service_ip" for the enrichment IP; accept both
						svcIP := item.ServiceIP
						if svcIP == "" {
							svcIP = item.IP
						}
						id, err = t.as.UpsertHTTPService(db.UpsertHTTPServiceReq{
							URL:           item.URL,
							Technologies:  item.Technologies,
							StatusCode:    item.StatusCode,
							ContentLength: item.ContentLength,
							PageTitle:     item.PageTitle,
							FaviconMMH3:   item.FaviconMMH3,
							Auth:          item.Auth,
							IP:            svcIP,
							TaskID:        taskID,
						})
					} else {
						id, err = t.as.UpsertOtherService(db.UpsertOtherServiceReq{
							Domain:      item.Domain,
							IP:          item.IP,
							Port:        item.Port,
							ServiceName: item.ServiceName,
							Auth:        item.Auth,
							TaskID:      taskID,
						})
					}

				case "endpoint":
					id, err = t.as.UpsertEndpoint(db.UpsertEndpointReq{
						URL:    item.URL,
						Method: item.Method,
						Params: item.Params,
						IP:     item.ServiceIP,
						TaskID: taskID,
					})

				default:
					errs = append(errs, errEntry{Index: i, Error: "unknown type: " + typ})
					continue
				}

				if err != nil {
					errs = append(errs, errEntry{Index: i, Error: err.Error()})
					continue
				}
				results = append(results, result{Index: i, ID: id, Type: typ})
				t.writes.Assets++
				t.anchorOwner(id)
				if taskID > 0 {
					var sourceNodeID *int64
					if t.ownerNode > 0 {
						nodeID := t.ownerNode
						sourceNodeID = &nodeID
					}
					summary := "Agent registered asset through insert_assets"
					if t.ownerNode > 0 {
						summary = fmt.Sprintf("Worker intent #%d registered asset through insert_assets", t.ownerNode)
					}
					_ = t.as.SetTaskAssetSource(taskID, id, "agent", summary, sourceNodeID)
				}
				// Auto-scope only explicitly inserted top-level Worker items at conservative type granularity;
				// derived side-effect assets do not expand scope. taskID=0 is a no-op.
				// Accumulate task_scope regardless of coverage settings: it bounds visibility and queries;
				// the switch only controls using that scope as a metric denominator.
				{
					svcIP := item.ServiceIP
					if svcIP == "" {
						svcIP = item.IP
					}
					_ = t.as.AddAutoScope(taskID, typ, item.Domain, item.URL, svcIP)
				}
			}

			return jsonResult(map[string]any{
				"results": results,
				"errors":  errs,
			})
		},
	)
}

// addCompanyScope writes to company_scope table and triggers asset attribution.
func (t *ToolSet) addCompanyScope() actool.CoreTool {
	return writeTool(
		"add_company_scope",
		"Add domains/IPs/CIDRs/ICP registrations/company keywords to a company's asset scope. Domains, networks, and ICP registrations automatically claim matching assets; keywords only provide scope hints to agents.\n"+
			"Company names are unique: create if absent, otherwise reuse and merge scope only.\n"+
			"One scope item per line, automatically recognized as root domain / URL / IP / CIDR / ICP registration / company keyword.\n"+
			"Always provide reason with ownership evidence (whois/certificate/ASN, etc.).\n"+
			"Guardrails: reject bare TLDs and overly broad networks (IPv4 prefixes /16-/32, IPv6 /32-/128). Skip invalid lines and return them in errors.",
		obj(map[string]any{
			"company": str("Unique company name; create if absent, otherwise reuse"),
			"scope":   str("Asset scope, one item per line: domain / URL / IP / CIDR / ICP registration / company keyword"),
			"reason":  str("Required ownership evidence/source"),
			"logo":    str("Optional company icon URL; used only when creating a company"),
		}, "company", "scope"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("add_company_scope disabled: CompanyStore is not initialized"), nil
			}
			var a struct {
				Company string `json:"company"`
				Scope   string `json:"scope"`
				Reason  string `json:"reason"`
				Logo    string `json:"logo"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if strings.TrimSpace(a.Company) == "" {
				return actool.Errorf("company must not be empty"), nil
			}
			companyID, _, err := t.cs.UpsertCompany(a.Company, a.Logo)
			if err != nil {
				return actool.Errorf("Failed to create/get company: " + err.Error()), nil
			}
			lines := splitLines(a.Scope)
			added, skipped, invalid, errMsgs := t.cs.AddScope(companyID, lines, a.Reason)
			out := map[string]any{
				"company_id": companyID,
				"added":      added,
				"skipped":    skipped,
				"invalid":    invalid,
			}
			if len(errMsgs) > 0 {
				out["errors"] = errMsgs
			}
			return jsonResult(out)
		},
	)
}

// addTaskScope lets the plan agent add test scope to THE CURRENT TASK — the coverage
// denominator and the task's authorization edge. Worker discoveries are auto-scoped
// (precise host) by insertAssets; this tool is for DELIBERATELY WIDENING: pull a whole
// root domain or whole company into scope, or add a specific subdomain / ip.
func (t *ToolSet) addTaskScope() actool.CoreTool {
	return writeTool(
		"add_task_scope",
		"Add testing scope to this task. This defines its authorization boundary and the denominator for asset testing coverage.\n"+
			"Supported kinds: company (all company assets) / root_domain (all subdomains) / subdomain (one exact subdomain) / ip / cidr / icp / keyword.\n"+
			"Hosts encountered by Workers are automatically added as exact subdomains. This tool actively expands scope to a whole root domain/company or a specified subdomain/IP.\n"+
			"value: company name or ID (must already exist); domain for root_domain/subdomain; IP/network for ip/cidr; registration number or company keyword for icp/keyword.\n"+
			"Always provide reason for auditing. Use entries for multiple items.",
		obj(map[string]any{
			"entries": map[string]any{"type": "array", "description": "Batch: [{kind,value}], kind in company/root_domain/subdomain/ip/cidr/icp/keyword.", "items": map[string]any{"type": "object"}},
			"kind":    str("[Single] company / root_domain / subdomain / ip / cidr / icp / keyword"),
			"value":   str("[Single] Company name/ID / domain / IP / CIDR / ICP / keyword"),
			"reason":  str("Required auditable reason for inclusion"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("add_task_scope disabled: AssetStore is not initialized"), nil
			}
			if t.taskID <= 0 {
				return actool.Errorf("add_task_scope requires task context (no current task)"), nil
			}
			type scopeEntry struct {
				Kind  string `json:"kind"`
				Value string `json:"value"`
			}
			var a struct {
				Entries    []scopeEntry `json:"entries"`
				scopeEntry              // Single mode.
				Reason     string       `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			items := a.Entries
			if len(items) == 0 {
				items = []scopeEntry{a.scopeEntry}
			}
			var added []map[string]any
			errs := map[string]string{}
			for i, e := range items {
				ts, err := t.as.AddAgentScope(t.taskID, strings.TrimSpace(e.Kind), e.Value, a.Reason, "agent")
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				added = append(added, map[string]any{"kind": ts.Kind, "domain": ts.Domain, "net": ts.Net, "value": ts.Value, "company_id": ts.CompanyID})
			}
			out := map[string]any{"added": added}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		},
	)
}

// listUntestedAssets lets the plan agent pull the current + directly inherited
// scope's not-yet-tested assets on demand (filter by type, paginated).
func (t *ToolSet) listUntestedAssets() actool.CoreTool {
	return readTool(
		"list_untested_assets",
		"Query assets in this task's or directly related tasks' scope that lack fact-anchor coverage. Inherited scope is read-only; decide yourself whether additional testing is needed.\n"+
			"Optional type filter: root_domain/subdomain/service/app/endpoint/ip.\n"+
			"Pagination: page starts at 1; page_size defaults to 10. Returns {assets:[{id,type,label}],total,page,page_size}. Requires task context.",
		obj(map[string]any{
			"type":      str("Optional type filter: root_domain/subdomain/service/app/endpoint/ip"),
			"page":      intp("Page number starting at 1 (default 1)"),
			"page_size": intp("Page size (default 10)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_untested_assets disabled: AssetStore is not initialized"), nil
			}
			if t.taskID <= 0 || t.ts == nil {
				return actool.Errorf("list_untested_assets requires task context"), nil
			}
			var a struct {
				Type     string `json:"type"`
				Page     int    `json:"page"`
				PageSize int    `json:"page_size"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Page <= 0 {
				a.Page = 1
			}
			if a.PageSize <= 0 {
				a.PageSize = 10
			}
			offset := (a.Page - 1) * a.PageSize
			assets, total, err := t.as.ListUntestedAssetsWithSources(t.taskID, strings.TrimSpace(a.Type), a.PageSize, offset)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"assets": assets, "total": total, "page": a.Page, "page_size": a.PageSize,
			})
		},
	)
}

// listAssets lets an agent query the asset table.
func (t *ToolSet) listAssets() actool.CoreTool {
	return readTool(
		"list_assets",
		"Query assets with a DSL expression or directly by id/ids; supports pagination. Returns only assets in this task's or directly related tasks' testing scope.\n"+
			"DSL: field=value fuzzy (ILIKE) | field==value exact | field!=value exclusion | numeric > >= < <= | bare word=full-text fuzzy. Combine AND/OR (AND has precedence) with parentheses. Supply asset type separately in type, not in DSL.\n"+
			"Without id/ids, dsl must be non-empty; unconditional full queries are prohibited.\n"+
			"Fields: domain (root/sub/service domain), root_domain, ip, url, page_title, icp, service_name, app_name, method (GET/POST), service_type(http|other), record_type(A/CNAME), technology (array, =fuzzy ==exact), port/status_code/company_id (integers).\n"+
			"Examples: status_code>=400 AND technology=shiro; (port==80 OR port==443) AND technology=nginx",
		obj(map[string]any{
			"dsl":    str(`DSL query (see description for syntax/fields); required when id/ids are absent`),
			"type":   str("Separate type filter: root_domain|ip|subdomain|app|service|endpoint, combined with dsl; type alone is insufficient"),
			"id":     intp("Optional direct asset ID, mutually exclusive with dsl/type"),
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Optional direct asset IDs, mutually exclusive with dsl/type"},
			"limit":  intp("Optional result limit, default 10"),
			"offset": intp("Optional pagination offset, default 0"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_assets disabled: AssetStore is not initialized"), nil
			}
			var a struct {
				DSL    string  `json:"dsl"`
				Type   string  `json:"type"`
				ID     int64   `json:"id"`
				IDs    []int64 `json:"ids"`
				Limit  int     `json:"limit"`
				Offset int     `json:"offset"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Limit <= 0 {
				a.Limit = 10
			}

			var assets []*db.Asset
			var err error
			switch {
			case a.ID > 0:
				assets, err = t.as.GetByIDsInScope(t.taskID, []int64{a.ID})
			case len(a.IDs) > 0:
				assets, err = t.as.GetByIDsInScope(t.taskID, a.IDs)
			case a.DSL != "":
				assets, err = t.as.QueryDSLInScope(a.DSL, a.Type, t.taskID, a.Limit, a.Offset)
			default:
				return actool.Errorf("dsl must not be empty without id/ids: unconditional asset queries are prohibited; supply query conditions"), nil
			}
			if err != nil {
				return actool.Errorf("DSL error: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"count":  len(assets),
				"assets": assets,
			})
		},
	)
}

// listCompanies enumerates companies with scope and asset counts.
func (t *ToolSet) listCompanies() actool.CoreTool {
	return readTool(
		"list_companies",
		"List companies with asset scope and assigned asset counts. Use to discover companies and "+
			"obtain company_id for insert_assets app association or list_assets company_id filtering."+
			"Optional case-insensitive company-name search; empty returns all.",
		obj(map[string]any{
			"search": str("Optional case-insensitive company-name filter; empty returns all"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("list_companies disabled: CompanyStore is not initialized"), nil
			}
			var a struct {
				Search string `json:"search"`
			}
			_ = json.Unmarshal(in, &a)
			cos, err := t.cs.ListCompanies()
			if err != nil {
				return actool.Errorf("Failed to query companies: " + err.Error()), nil
			}
			q := strings.ToLower(strings.TrimSpace(a.Search))
			type companyOut struct {
				ID         int64    `json:"id"`
				Name       string   `json:"name"`
				AssetCount int      `json:"asset_count"`
				Scope      []string `json:"scope"`
			}
			out := make([]companyOut, 0, len(cos))
			for _, c := range cos {
				if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
					continue
				}
				scope := make([]string, 0, len(c.Scope))
				for _, r := range c.Scope {
					scope = append(scope, r.Raw)
				}
				out = append(out, companyOut{ID: c.ID, Name: c.Name, AssetCount: c.AssetCount, Scope: scope})
			}
			return jsonResult(map[string]any{"count": len(out), "companies": out})
		},
	)
}

// splitLines splits a multi-line string into non-empty trimmed lines.
func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// WorkerTools returns the tool set for a work agent.
func (t *ToolSet) WorkerTools() []actool.CoreTool {
	ws := []actool.CoreTool{
		// Retain list_findings so Workers check confirmed findings before reporting duplicates.
		t.listFindings(),
		t.addFinding(), t.recordFact(),
		// asset management (handlers guard nil store internally).
		// Workers cannot add_company_scope; company boundaries belong to planning/mainagent/Auto.
		t.insertAssets(), t.listAssets(),
		// Workers may review other work to reuse observations and avoid duplicate effort.
		// search_all_worker_traces finds matching steps without a known intent_id;
		// get_worker_trace lists/searches one work and returns full step content.
		t.searchAllWorkerTraces(), t.getWorkerTrace(),
		// node_detail reads full details after a Worker obtains an intent/node ID through trace review.
		t.nodeDetail(),
		// list_facts/list_companies/list_worker_traces remain planner/main-only; contextual review
		// is a planning responsibility, while Workers execute and persist one intent.
	}
	ws = append(ws, t.assuranceTools()...)
	// Mobile-assessment capability tools (bypass library + Burp-MCP traffic surface)
	// let the worker drive static-protection defeat and authenticated API testing.
	ws = append(ws, t.mobileTools()...)
	return ws
}

// MainAgentTools returns the human-interface tool set.
func (t *ToolSet) MainAgentTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(), t.listFindings(), t.listFacts(), t.nodeDetail(),
		t.expandDigest(), // cold-digest §6.1
		t.getWorkerOutput(), t.getWorkerTrace(), t.searchAllWorkerTraces(), t.addHint(), t.addIntent(),
		// steer_work injects human corrections into running work without interruption or lost progress.
		t.steerWorkTool(),
		// set_goals adds a runtime final goal for the planner to reassess.
		t.setGoals(),
		// set_constraints adds/changes runtime allow/deny exploration boundaries.
		t.setConstraints(),
		// asset management (handlers guard nil store internally)
		t.insertAssets(), t.addCompanyScope(), t.listAssets(),
		t.addFinding(), t.recordFact(),
		t.addTaskScope(),
		// list_untested_assets provides type/pagination for deciding whether to test uncovered assets.
		t.listUntestedAssets(),
	}
}

// AllDomainTools returns the union of all domain tools across all agent types,
// deduped by name (mainagent order wins). Used by the server to build a registry
// for injecting domain tools into agents (Auto, custom) that don't own a per-task
// ToolSet. The caller provides real stores; tools are callable at taskID=0 scope.
func (t *ToolSet) AllDomainTools() []actool.CoreTool {
	seen := map[string]bool{}
	var out []actool.CoreTool
	all := append(append(t.MainAgentTools(), t.PlannerTools()...), t.WorkerTools()...)
	for _, tool := range all {
		if !seen[tool.Name()] {
			seen[tool.Name()] = true
			out = append(out, tool)
		}
	}
	return out
}
