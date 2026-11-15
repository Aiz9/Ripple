package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/internal/devicelab"
	"github.com/Autumn-27/artex/internal/staticx"
	actool "github.com/Autumn-27/norma/tool"
)

func errf(format string, a ...any) actool.Result { return actool.Errorf(fmt.Sprintf(format, a...)) }

// clipHTTPMessage truncates an HTTP message to max bytes, marking the cut so the agent
// knows to raise max_body if it needs more.
func clipHTTPMessage(s string, max int) string {
	if max > 0 && len(s) > max {
		return s[:max] + "\n…[truncated; raise max_body for more]"
	}
	return s
}

// Mobile-assessment capability tools. These expose the deterministic modules the
// agent reasons over during a mobile app assessment: the client-protection bypass
// library (what defeats root/pinning/Flutter-TLS, with ready Frida scripts) and
// the Burp-MCP traffic surface (read decrypted history, replay for authz/IDOR).
// The LLM selects and sequences; the modules carry the hard, exact work.

func strArr(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}
func strField(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
func intField(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func (t *ToolSet) mobileListBypasses() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"native_libs":    strArr("APK/IPA native lib paths or names (e.g. libflutter.so) from static facts"),
			"source_signals": strArr("protection signals from the decompiled-source scan (e.g. okhttp3.CertificatePinner, RootBeer)"),
		},
		"additionalProperties": false,
	}
	return readTool("mobile_list_bypasses",
		"List the client-protection bypasses applicable to this app (root detection, SSL pinning, Flutter BoringSSL TLS) and return a ready-to-inject Frida script. Reason over native_libs + source_signals; the byte patterns are maintained, not invented. After injecting, confirm the ssl_bypass_applied events actually fire — a 'no pattern matched' limitation means the app pins via another path.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var args struct {
				NativeLibs    []string `json:"native_libs"`
				SourceSignals []string `json:"source_signals"`
			}
			_ = json.Unmarshal(in, &args)
			facts := &staticx.Facts{NativeLibs: args.NativeLibs}
			bypasses := devicelab.ApplicableBypasses(facts, args.SourceSignals)
			if len(bypasses) == 0 {
				return actool.Text(`{"bypasses":[],"note":"no known protection detected; app may run unmodified or pin via an unrecognized path"}`), nil
			}
			type info struct {
				ID, Title, Category, Notes string
			}
			var list []info
			for _, b := range bypasses {
				list = append(list, info{b.ID, b.Title, b.Category, b.Notes})
			}
			out, _ := json.Marshal(map[string]any{
				"bypasses":     list,
				"frida_script": devicelab.GenerateFridaBypassScript(bypasses),
			})
			return actool.Text(string(out)), nil
		})
}

func (t *ToolSet) mobileTrafficHistory() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":        strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"offset":         intField("history offset (default 0)"),
			"count":          intField("max items (default 200)"),
			"host_filter":    strField("optional case-insensitive host substring filter"),
			"include_bodies": map[string]any{"type": "boolean", "description": "include each exchange's full request AND response text (headers + body), truncated to max_body — needed to inspect parameters/object-IDs and to diff responses across identities for IDOR/BOLA"},
			"max_body":       intField("per-message truncation cap in bytes when include_bodies is set (default 4096, max 65536)"),
		},
		"additionalProperties": false,
	}
	return readTool("mobile_traffic_history",
		"PRIMARY — the top-priority source of truth for the app's live API surface. Reads decrypted HTTP exchanges captured by Burp (via its MCP server): the app's REAL traffic (CA + proxy are already configured). Returns host/method/path per item (plus the item's `index` for replay); set include_bodies to also get the full request+response so you can inspect parameters/object-IDs and establish the baseline response for authz/IDOR comparison. Prefer these endpoints over ones merely inferred from decompiled code; use mobile_ui_* to drive the app and generate more.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var args struct {
				MCPURL        string `json:"mcp_url"`
				Offset        int    `json:"offset"`
				Count         int    `json:"count"`
				HostFilter    string `json:"host_filter"`
				IncludeBodies bool   `json:"include_bodies"`
				MaxBody       int    `json:"max_body"`
			}
			_ = json.Unmarshal(in, &args)
			if args.MCPURL == "" {
				args.MCPURL = devicelab.BurpMCPURL()
			}
			if args.Count == 0 {
				args.Count = 200
			}
			if args.MaxBody <= 0 {
				args.MaxBody = 4096
			}
			if args.MaxBody > 65536 {
				args.MaxBody = 65536
			}
			c, err := devicelab.DialBurpMCP(ctx, args.MCPURL)
			if err != nil {
				return errf("connect Burp MCP: %v", err), nil
			}
			defer c.Close()
			ex, err := c.ProxyHistory(ctx, args.Offset, args.Count)
			if err != nil {
				return errf("read history: %v", err), nil
			}
			type row struct {
				Index              int `json:"index"` // absolute position (offset+i), use with mobile_traffic_replay history_index
				Host, Method, Path string
				Request            string `json:"request,omitempty"`
				Response           string `json:"response,omitempty"`
			}
			var rows []row
			hf := strings.ToLower(args.HostFilter)
			for i, e := range ex {
				if hf != "" && !strings.Contains(strings.ToLower(e.Host), hf) {
					continue
				}
				r := row{Index: args.Offset + i, Host: e.Host, Method: e.Method, Path: e.Path}
				if args.IncludeBodies {
					r.Request = clipHTTPMessage(e.Request, args.MaxBody)
					r.Response = clipHTTPMessage(e.Response, args.MaxBody)
				}
				rows = append(rows, r)
			}
			out, _ := json.Marshal(map[string]any{"count": len(rows), "exchanges": rows})
			return actool.Text(string(out)), nil
		})
}

func (t *ToolSet) mobileTrafficReplay() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mcp_url":       strField("Burp MCP server URL (default http://127.0.0.1:9876)"),
			"host":          strField("target host (required unless history_index sources it)"),
			"port":          intField("target port (default 443, or 80 when tls=false)"),
			"tls":           map[string]any{"type": "boolean", "description": "use HTTPS (default true)"},
			"request":       strField("raw HTTP/1.1 request (CRLF line endings); omit when using history_index"),
			"history_index": intField("instead of request, replay the captured exchange at this absolute history index (from mobile_traffic_history) — its request/host/tls are used verbatim"),
			"as_role":       strField("replay AS this registered identity (mobile_identity_set): its auth headers replace the request's, to test if identity A's object is reachable with identity B's credentials (IDOR/BOLA)"),
		},
		"additionalProperties": false,
	}
	return writeTool("mobile_traffic_replay",
		"Replay/issue a request through Burp. The IDOR/BOLA primitive: set history_index to re-send a captured exchange and as_role to send it as a DIFFERENT identity — then compare the response to the owner's baseline (mobile_traffic_history include_bodies). A 2xx alone does not prove a vulnerability; unauthorized DISCLOSURE or EFFECT does. Also use it for business-logic tests (tamper amounts/quantities/state) and injection/validation checks. Provide either `request`+`host` or `history_index`.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var args struct {
				MCPURL       string `json:"mcp_url"`
				Host         string `json:"host"`
				Port         int    `json:"port"`
				TLS          *bool  `json:"tls"`
				Request      string `json:"request"`
				HistoryIndex *int   `json:"history_index"`
				AsRole       string `json:"as_role"`
			}
			if err := json.Unmarshal(in, &args); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if args.MCPURL == "" {
				args.MCPURL = devicelab.BurpMCPURL()
			}
			tls := true
			if args.TLS != nil {
				tls = *args.TLS
			}
			c, err := devicelab.DialBurpMCP(ctx, args.MCPURL)
			if err != nil {
				return errf("connect Burp MCP: %v", err), nil
			}
			defer c.Close()
			// Source the request from captured history when an index is given.
			if args.HistoryIndex != nil {
				idx := *args.HistoryIndex
				if idx < 0 {
					return actool.Errorf("history_index must be >= 0"), nil
				}
				ex, herr := c.ProxyHistory(ctx, idx, 1)
				if herr != nil {
					return errf("read history: %v", herr), nil
				}
				if len(ex) == 0 {
					return errf("no captured exchange at history_index %d", idx), nil
				}
				args.Request = ex[0].Request
				if args.Host == "" {
					args.Host = ex[0].Host
				}
				if args.TLS == nil {
					tls = ex[0].TLS
				}
			}
			if args.Host == "" || args.Request == "" {
				return actool.Errorf("provide either request+host or history_index"), nil
			}
			if args.AsRole != "" {
				id, ok := getIdentity(t.taskID, args.AsRole)
				if !ok {
					return errf("unknown identity role %q; register it with mobile_identity_set first", args.AsRole), nil
				}
				args.Request = applyIdentityHeaders(args.Request, id.Headers)
			}
			if args.Port == 0 {
				if tls {
					args.Port = 443
				} else {
					args.Port = 80
				}
			}
			resp, err := c.SendRequest(ctx, args.Host, args.Port, tls, args.Request)
			if err != nil {
				return errf("replay: %v", err), nil
			}
			return actool.Text(resp), nil
		})
}

func (t *ToolSet) mobileCaptureStatus() actool.CoreTool {
	schema := map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}
	return readTool("mobile_capture_status",
		"PRIMARY — call this FIRST. Burp MCP traffic is the top-priority data source for this assessment (an intercepting proxy with a device-trusted CA is configured, so real HTTPS/API traffic is captured live). Verifies the Burp MCP capture integration: connects to the configured Burp MCP server (ANDROIDLAB_BURP_MCP_URL, default http://127.0.0.1:9876), runs the handshake, and confirms proxy history is available. If it is not ready, the traffic tools will fail.",
		schema,
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			ok, detail := devicelab.CheckBurpMCP(ctx)
			out, _ := json.Marshal(map[string]any{"ready": ok, "detail": detail, "url": devicelab.BurpMCPURL()})
			return actool.Text(string(out)), nil
		})
}

func (t *ToolSet) mobileDiscoverRuntimeAPIs() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"package":        strField("target app package name (e.g. com.example.app)"),
			"seconds":        intField("instrumentation window in seconds (3–300, default 25)"),
			"native_libs":    strArr("APK native lib names from static facts (selects applicable bypasses, e.g. libflutter.so)"),
			"source_signals": strArr("protection signals from the decompiled-source scan (selects applicable bypasses, e.g. okhttp3.CertificatePinner, RootBeer)"),
		},
		"required":             []any{"package"},
		"additionalProperties": false,
	}
	return readTool("mobile_discover_runtime_apis",
		"Discover the app's RUNTIME API surface: spawn the app under Frida with HTTP-client instrumentation (OkHttp/Retrofit, HttpURLConnection) and record every request it makes during the window — method + URL — captured at the client call site BEFORE TLS. This surfaces endpoints that never reach the proxy and ones built dynamically at runtime, which static URL extraction and mobile_traffic_history miss. Requires root (Frida); client-protection bypasses are applied automatically. The spawn captures the startup/auto-login burst; to reach authenticated flows, drive the app with mobile_ui_* and re-run, and correlate with mobile_traffic_history.",
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var args struct {
				Package       string   `json:"package"`
				Seconds       int      `json:"seconds"`
				NativeLibs    []string `json:"native_libs"`
				SourceSignals []string `json:"source_signals"`
			}
			if err := json.Unmarshal(in, &args); err != nil {
				return errf("bad arguments: %v", err), nil
			}
			if strings.TrimSpace(args.Package) == "" {
				return actool.Errorf("package is required"), nil
			}
			if args.Seconds == 0 {
				args.Seconds = 25
			}
			dev, err := t.mobileDevice(ctx, args.Package)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if dev.DetectRoot(ctx); !dev.HasRoot() {
				return actool.Errorf("runtime API discovery requires root (Frida); this device has no root. Use mobile_traffic_history for proxy-observed endpoints instead."), nil
			}
			facts := &staticx.Facts{NativeLibs: args.NativeLibs}
			bypasses := devicelab.ApplicableBypasses(facts, args.SourceSignals)
			stateDir := strings.TrimSpace(os.Getenv("ANDROIDLAB_STATE_DIR"))
			if stateDir == "" {
				stateDir = filepath.Join(os.TempDir(), "artex-devicelab")
			}
			eps, events, err := dev.DiscoverRuntimeAPIs(ctx, bypasses, args.Seconds, strings.TrimSpace(os.Getenv("ANDROIDLAB_FRIDA_SERVER")), stateDir)
			if err != nil {
				return errf("runtime capture failed: %v", err), nil
			}
			var limitations []string
			for _, e := range devicelab.EventsOfKind(events, "limitation") {
				if d, ok := e["detail"].(string); ok {
					limitations = append(limitations, d)
				}
			}
			out, _ := json.Marshal(map[string]any{
				"endpoints":      eps,
				"count":          len(eps),
				"bypass_applied": len(devicelab.EventsOfKind(events, "ssl_bypass_applied")),
				"limitations":    limitations,
				"note":           "Runtime endpoints captured at the HTTP-client layer. Drive the app (mobile_ui_*) and re-run to reach authenticated flows; correlate with mobile_traffic_history and static URLs.",
			})
			return actool.Text(string(out)), nil
		})
}

// mobileTools is the set of mobile-assessment capability tools, appended to the
// worker's toolset so the autonomous (local-LLM) reasoning loop can drive them.
func (t *ToolSet) mobileTools() []actool.CoreTool {
	return []actool.CoreTool{
		// PRIMARY: Burp MCP traffic is the top-priority data source (CA + proxy
		// are configured). Lead with capture status + traffic history/replay.
		t.mobileCaptureStatus(),
		t.mobileTrafficHistory(),
		t.mobileTrafficReplay(),
		// Systematic, deterministic endpoint discovery: normalize+dedup Burp
		// history into the assets inventory, instead of ad-hoc insert_assets.
		t.mobileAPIHarvest(),
		// API relationship/dependency graph: objects + producer→consumer id edges,
		// to chain flows and target BOLA.
		t.mobileAPIGraph(),
		// OpenAPI/Swagger ingestion: documented endpoints as a distinct INFERRED
		// layer, to exercise and to diff against observed (shadow detection).
		t.mobileOpenAPIIngest(),
		// Schema-driven robustness probe: mutate a captured request's fields and
		// flag 5xx (unhandled malformed input). Targeted, not blind fuzzing.
		t.mobileSchemaFuzz(),
		// Mass assignment: inject privilege fields the request omitted; a finding
		// only when the response shows the injected value was applied (reflected).
		t.mobileMassAssignment(),
		// Injection: SSTI (evaluated-expression reflection) + error-based SQLi
		// (DB error signature); confirmed by evidence, not status.
		t.mobileInjectProbe(),
		// Multi-identity store: register controlled test accounts (user_a, user_b,
		// admin) so captured requests can be replayed as another principal for
		// object/function authorization testing (IDOR/BOLA).
		t.mobileIdentitySet(),
		t.mobileIdentityList(),
		// Deterministic IDOR/BOLA verifier: replay the owner's request as another
		// identity (and unauthenticated) and decide by fixed evidence rules, not by
		// eye — a 2xx never confirms on its own.
		t.mobileAuthzDiff(),
		t.mobileAuthzSweep(),
		// Configurable authorization expectations: declare legitimately-shared
		// endpoints so expected access is not reported as IDOR/BOLA.
		t.mobileAuthzExpect(),
		t.mobileAuthzExpectList(),
		// Deterministic financial business-logic tester: tamper a captured
		// transaction against configured invariants (amount/limit/currency/
		// idempotency); a finding only when the server accepts a violation.
		t.mobileTxnProbe(),
		// Authentication testing (JWT): static decode + active alg:none / tampered-
		// signature replays; a finding only when a must-reject token is accepted.
		t.mobileJWTProbe(),
		// Race/TOCTOU: fire K identical requests concurrently; a finding only when
		// more acceptances than legitimate occur (double-spend/limit bypass).
		t.mobileRaceProbe(),
		// Workflow state machine: detect accepted out-of-order / skipped-prerequisite
		// steps in a multi-step financial flow.
		t.mobileWorkflowSet(),
		t.mobileWorkflowCheck(),
		t.mobileListBypasses(),
		// Runtime API discovery: Frida HTTP-client instrumentation captures the
		// endpoints the app actually calls, including off-proxy and dynamically
		// built ones (requires root).
		t.mobileDiscoverRuntimeAPIs(),
		// No-root adb UI automation (see mobileui_tools.go): drive the app on an
		// attached Genymotion/emulator/device without root, chiefly to GENERATE
		// the traffic Burp then captures.
		t.mobileDeviceStatus(),
		t.mobileLaunchApp(),
		t.mobileUIDump(),
		t.mobileUITap(),
		t.mobileUISwipe(),
		t.mobileUIType(),
		t.mobileUIKey(),
	}
}
