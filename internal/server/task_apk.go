package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/Aiz9/ripple/internal/androidapk"
	"github.com/Aiz9/ripple/internal/db"
	"github.com/Aiz9/ripple/internal/mobiletest"
)

// createAPKTaskReq creates a standard web task whose target is an uploaded APK
// instead of a web URL. The APK runs through the SAME pipeline as a web target
// (goals → planner → worker agents → exploration graph → the Current tasks UI);
// only the seeded objective and target differ. The APK is already uploaded via
// POST /api/android/apps; its id (SHA-256) is passed here.
type createAPKTaskReq struct {
	APKID string `json:"apk_id"`
	Name  string `json:"name,omitempty"`
	// Description and Goal, when non-empty, are used VERBATIM — the operator edits the
	// pre-filled MASVS template in the dialog and owns the task's description/goal. Each
	// falls back to the generated default only when left blank (older clients / API use).
	Description    string   `json:"description,omitempty"`
	Goal           string   `json:"goal,omitempty"`
	Objective      string   `json:"objective,omitempty"`   // legacy: extra objective, used only when Description is blank
	ScopeHosts     []string `json:"scope_hosts,omitempty"` // optional in-scope backend hosts
	LLMProfileID   *int64   `json:"llm_profile_id,omitempty"`
	LLMProfileIDs  []int64  `json:"llm_profile_ids,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
}

// createAPKTask handles POST /api/tasks/apk.
func (s *Server) createAPKTask(w http.ResponseWriter, r *http.Request) {
	var req createAPKTaskReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(req.APKID) == "" {
		writeErr(w, 400, "apk_id is required (upload the APK first via POST /api/android/apps)")
		return
	}
	app, err := s.readAndroidApp(req.APKID)
	if err != nil || app.Report == nil {
		writeErr(w, 400, "APK not found; upload it first via POST /api/android/apps")
		return
	}
	if len(req.LLMProfileIDs) == 0 && req.LLMProfileID != nil {
		req.LLMProfileIDs = []int64{*req.LLMProfileID}
	}
	if err := s.validateTaskProfileIDs(req.LLMProfileIDs); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.TimeoutSeconds < 0 {
		req.TimeoutSeconds = 0
	}

	pkg := app.Report.Package
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "APK: " + pkg
	}
	// Operator-supplied text wins; the generated MASVS template is only the default
	// shown pre-filled in the dialog, so an edited (or cleared-and-rewritten) field is
	// honored as-is. Blank falls back to the default (older clients, raw API callers).
	description := strings.TrimSpace(req.Description)
	if description == "" {
		description = apkTaskDescription(app, req.ScopeHosts, req.Objective)
	}
	goal := strings.TrimSpace(req.Goal)
	if goal == "" {
		goal = apkTaskGoal(pkg)
	}
	// Tag the task as an APK assessment (same marker seed() recognizes). This both
	// stops seed() from inferring a network target AND lets createGoals seed the
	// catalog-driven phase flow instead of one generic goal. The operator's edited
	// MASVS text is preserved below the marker line.
	description = "[Android APK: " + app.ID + "]\n" + description

	t, err := s.m.CreateTaskWithOptions(description, goal, db.TaskCreateOptions{
		Name:           name,
		LLMProfileIDs:  req.LLMProfileIDs,
		TimeoutSeconds: req.TimeoutSeconds,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	log.Printf("[task] created APK task #%s package=%s apk=%s", t.ID, pkg, req.APKID)
	// Same launch path as a web task: background goal decomposition + engine start.
	s.launchTask(t, description+" "+goal, false)
	writeJSON(w, 201, taskDTO(t, s.resolvedTaskStatus(t)))
}

// apkMarkerID extracts the APK id from a task description tagged by createAPKTask
// ("[Android APK: <id>]" on the first line), matching seed()'s convention. It is
// how createGoals recognises an APK task without a schema change.
func apkMarkerID(description string) (string, bool) {
	line := description
	if i := strings.IndexByte(description, '\n'); i >= 0 {
		line = description[:i]
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "[Android APK: ") {
		return "", false
	}
	id, _, ok := strings.Cut(strings.TrimPrefix(line, "[Android APK: "), "]")
	id = strings.TrimSpace(id)
	if !ok || !apkIDPattern.MatchString(id) {
		return "", false
	}
	return id, true
}

// apkRuntimeFirstOrder lists catalog section numbers in the execution order the
// APK task seeds them: scoping, then on-device dynamic setup, then RUNTIME app
// checks (auth, storage, crypto, platform/IPC, resilience), then RUNTIME API
// testing and business logic — with the static-analysis sections (information
// gathering, static analysis, build hygiene) reordered AFTER as support, and
// reporting last. This keeps the same catalog (so MASVS scoring is unchanged) but
// makes the planner lead with dynamic/runtime work instead of static. Sections
// not listed keep their catalog order after the listed ones.
var apkRuntimeFirstOrder = []int{1, 4, 6, 7, 8, 9, 10, 5, 11, 2, 3, 12, 13}

// apkSupportSections are the static/offline phases positioned as support: they
// corroborate and explain runtime evidence and must not block runtime testing.
var apkSupportSections = map[int]bool{2: true, 3: true, 12: true}

func apkPhaseRank(section int) int {
	for i, s := range apkRuntimeFirstOrder {
		if s == section {
			return i
		}
	}
	return len(apkRuntimeFirstOrder) + section // unlisted sections trail, in section order
}

// apkPhaseGoals renders the mobiletest catalog Flow() into ordered, per-phase
// goals (hybrid coverage-driven): the planner works one intent per catalog
// procedure per phase and must resolve each (done / blocked / not-applicable +
// evidence), instead of free-forming from one broad MASVS objective. Phases are
// emitted RUNTIME-FIRST (see apkRuntimeFirstOrder); the signals line is framed as
// supporting input gathered on demand rather than a static-before-runtime gate.
func apkPhaseGoals() []goalSpec {
	flow := mobiletest.Flow()
	sort.SliceStable(flow, func(i, j int) bool {
		return apkPhaseRank(flow[i].Index) < apkPhaseRank(flow[j].Index)
	})
	specs := make([]goalSpec, 0, len(flow))
	for step, p := range flow {
		var b strings.Builder
		var kind string
		switch {
		case apkSupportSections[p.Index]:
			kind = "SUPPORT (static) — use on demand to corroborate/explain runtime evidence; do not block runtime testing on it"
		case p.Index == 1 || p.Index == 13:
			kind = "methodology"
		default:
			kind = "RUNTIME/dynamic — lead with this"
		}
		fmt.Fprintf(&b, "Step %02d of %02d — Phase %02d %s [%s]. Work every procedure below; for each, record done / blocked / not-applicable with concrete evidence (file:line, tool output, or captured request). Do not skip silently.\n", step+1, len(flow), p.Index, p.Name, kind)
		for _, c := range p.Controls {
			fmt.Fprintf(&b, "- [%s] %s — %s\n", c.ID, c.Title, c.Procedure)
		}
		if len(p.Requires) > 0 {
			fmt.Fprintf(&b, "Prerequisites (resolve or mark blocked): %s.\n", strings.Join(p.Requires, ", "))
		}
		if len(p.Signals) > 0 {
			fmt.Fprintf(&b, "Supporting inputs (gather on demand, including via static analysis): %s.\n", strings.Join(p.Signals, ", "))
		}
		specs = append(specs, goalSpec{Text: strings.TrimRight(b.String(), "\n"), VulnClass: strings.Join(p.Objectives, ",")})
	}
	return specs
}

// apkStaticInventory renders the static endpoint inventory extracted at upload as
// a bounded, agent-readable list (URL, with owning class where known). It is the
// "every static endpoint" baseline the agent must verify/trigger at runtime.
func apkStaticInventory(app *androidApp) string {
	if len(app.StaticURLs) == 0 {
		return ""
	}
	const max = 300
	var urls, paths []androidapk.URLObservation
	for _, u := range app.StaticURLs {
		if u.Kind == "path" {
			paths = append(paths, u)
		} else {
			urls = append(urls, u)
		}
	}
	var b strings.Builder
	b.WriteString("STATIC API INVENTORY (extracted from the APK). The base URL is frequently switched at RUNTIME (build flavor, remote config, environment toggle), so treat the base URL OBSERVED IN PROXY TRAFFIC as authoritative and combine these with it.\n")
	if len(urls) > 0 {
		fmt.Fprintf(&b, "\nBase/full URLs (%d) — candidate hosts; confirm which the app actually uses at runtime:\n", len(urls))
		writeObs(&b, urls, max)
	}
	if len(paths) > 0 {
		fmt.Fprintf(&b, "\nEndpoint path templates (%d) — host-less routes declared in code (Retrofit/OkHttp). Join each to the runtime base URL; TRIGGER any that never appear in proxy traffic (code-declared but unobserved = shadow/untested):\n", len(paths))
		writeObs(&b, paths, max)
	}
	return b.String()
}

func writeObs(b *strings.Builder, obs []androidapk.URLObservation, max int) {
	for i, u := range obs {
		if i >= max {
			fmt.Fprintf(b, "- …and %d more (decompile + grep for the full list).\n", len(obs)-max)
			return
		}
		if u.Owner != "" {
			fmt.Fprintf(b, "- %s  (%s)\n", u.URL, u.Owner)
		} else {
			fmt.Fprintf(b, "- %s\n", u.URL)
		}
	}
}

// apkTaskGoal is the default MASVS findings-report goal for an APK task, used to
// pre-fill the dialog and as the fallback when the operator leaves the goal blank.
func apkTaskGoal(pkg string) string {
	return fmt.Sprintf("Produce an OWASP MASVS v2-aligned findings report for the Android app %s: identify insecure storage, hardcoded secrets, weak cryptography, missing TLS/certificate pinning or cleartext traffic, exported-component/WebView/IPC exposure, authentication/session weaknesses, vulnerable third-party dependencies (CVEs), weak native hardening, and resilience/attestation gaps — each backed by concrete evidence.", pkg)
}

// apkTaskTemplate handles GET /api/tasks/apk/template?apk_id=<sha256>. It returns the
// default MASVS description and goal for an uploaded APK so the dialog can pre-fill
// them as editable text, rather than regenerating server-side at create time.
func (s *Server) apkTaskTemplate(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("apk_id"))
	if id == "" {
		writeErr(w, 400, "apk_id is required")
		return
	}
	app, err := s.readAndroidApp(id)
	if err != nil || app.Report == nil {
		writeErr(w, 400, "APK not found; upload it first via POST /api/android/apps")
		return
	}
	writeJSON(w, 200, map[string]string{
		"description": apkTaskDescription(app, nil, ""),
		"goal":        apkTaskGoal(app.Report.Package),
	})
}

// apkTaskDescription builds the seeded objective that steers the standard web
// agents to audit a local APK with their existing tools. The web worker already
// carries Bash and the mobile_* tools; this tells it the target is an APK file
// (not a URL), where it is, and how to work it against MASVS.
func apkTaskDescription(app *androidApp, scopeHosts []string, extra string) string {
	var b strings.Builder
	pkg := app.Report.Package
	fmt.Fprintf(&b, "Android APK security assessment (OWASP MASVS v2) of package %q.\n\n", pkg)
	b.WriteString("TARGET IS A LOCAL ANDROID APK (authorized for testing), not a web URL.\n")
	fmt.Fprintf(&b, "- Package: %s\n", pkg)
	fmt.Fprintf(&b, "- APK file (absolute path on this host): %s\n", app.APKPath)
	fmt.Fprintf(&b, "- SHA-256: %s\n", app.ID)
	b.WriteString("\nRUNTIME-FIRST STRATEGY — this is a dynamic (on-device) VAPT of the live app AND of the APIs it calls at runtime. Lead with on-device dynamic work in this order: (1) device + instrumentation setup, (2) RUNTIME app checks (auth/session, local storage, crypto/Keystore, platform/IPC/WebView, resilience), (3) RUNTIME API/endpoint testing (discover the endpoints the app actually calls, then authorization/IDOR/BOLA and business logic). Static analysis (decompilation, manifest, secrets, dependency CVEs) is SUPPORT — run it on demand to corroborate and explain runtime evidence, not as the first or primary activity. The seeded phase goals are ordered to match.\n")
	b.WriteString("\nSTEP 1 — ENDPOINT ENUMERATION IS MANDATORY AND EXHAUSTIVE. Build ONE merged endpoint inventory (method + host + path, each tagged with source and auth-state) from THREE sources across TWO authentication states. Do not start vulnerability testing until the surface is enumerated.\n")
	b.WriteString("A. STATIC — every endpoint embedded in the APK. A pre-extracted static inventory is listed below; ALSO decompile (`jadx -d <out> <apk>`) and `grep -rniE 'https?://|@(GET|POST|PUT|DELETE|PATCH)\\(|/v[0-9]+/|/api/|baseUrl|Retrofit'` the sources to recover RELATIVE route templates (e.g. Retrofit `@GET(\"v1/accounts/{id}\")`) and base-URL joins that a literal-URL scan misses.\n")
	b.WriteString("B. RUNTIME, BEFORE LOGIN (unauthenticated surface): `mobile_device_status` + `mobile_capture_status` (confirm device online + Burp ready), `mobile_launch_app`, then IMMEDIATELY `mobile_discover_runtime_apis` and `mobile_traffic_history` to capture every request the app makes on startup and on the login/onboarding screens — BEFORE authenticating.\n")
	b.WriteString("C. LOG IN RELIABLY — do NOT skip this or give up after one attempt (flaky login is the top cause of missed surface). `mobile_ui_dump`, locate the username/password fields by their node refs, `mobile_ui_type` the credentials, submit, then `mobile_ui_dump` AGAIN to CONFIRM the authenticated/home screen actually appeared. If it did not, retry: re-dump, re-locate fields, handle OTP/2FA/consent screens, try alternate login entry points. Only mark login blocked after several attempts, with concrete evidence. Register the accounts you use with `mobile_identity_set`.\n")
	b.WriteString("D. RUNTIME, AFTER LOGIN (authenticated surface): drive EVERY major screen and flow with `mobile_ui_*`, and after each, call `mobile_discover_runtime_apis` + `mobile_traffic_history` so Frida/Burp capture the authenticated API calls. Keep exploring until new screens stop yielding new endpoints.\n")
	b.WriteString("E. MERGE static + runtime-preauth + runtime-postauth + proxy into one inventory; for each endpoint record its source, method, and whether it required authentication. (`mobile_list_bypasses` applies static-protection defeats if expected traffic is missing; there is NO separate 'burp'/'mcp__burp__' tool — `mobile_traffic_history`/`mobile_traffic_replay`/`mobile_capture_status` ARE the Burp MCP interface.)\n")
	b.WriteString("\nSTEP 2 — TEST EVERY ENUMERATED ENDPOINT for OWASP API Security Top 10, OWASP Top 10, and business-logic flaws. Register controlled accounts with `mobile_identity_set` (e.g. user_a owning account/beneficiary A, user_b owning B, admin); use `mobile_traffic_history` include_bodies for baselines and `mobile_traffic_replay` with `history_index` + `as_role`:\n")
	b.WriteString("- BOLA / IDOR (API1): replay one identity's object request as another (`as_role=user_b`) — unauthorized DISCLOSURE or EFFECT, not a bare 2xx, proves it.\n")
	b.WriteString("- Broken authentication (API2): token/session reuse after logout, expiry, accessing post-login endpoints pre-login or with no token.\n")
	b.WriteString("- BOPLA / mass assignment (API3): add fields such as is_admin, role, amount, verified, status to request bodies and check they take effect.\n")
	b.WriteString("- BFLA (API5): invoke admin/privileged functions as a low-privilege identity.\n")
	b.WriteString("- Unrestricted business flows (API6) & BUSINESS LOGIC: tamper amount/quantity/currency, negative/overflow/decimal values, invalid state transitions, replay/duplicate transactions, skip required steps, race conditions; verify server-side invariants (e.g. balance_before − balance_after = amount_debited).\n")
	b.WriteString("- Injection, SSRF, and excessive data exposure where the endpoint's parameters allow. Every finding needs cross-identity or baseline-vs-tampered response evidence.\n")
	b.WriteString("REPLAY MECHANICS (read before authz testing): (1) ALL egress from this task — including Bash curl — is captured by the same Burp, so `mobile_traffic_replay` and direct HTTP hit the identical proxy; prefer the tool so `as_role` and the authz sweep work, and do NOT conclude the replay/authz tools are \"broken\" or \"env-specific\" from a target 4xx or an argument error — report the exact tool error instead. (2) `history_index` is an absolute position that shifts as traffic is captured/rotated — re-read `mobile_traffic_history` right before an index replay, or pass `request`+`host` explicitly. (3) Identity tokens are static; if the target is single-session (a new login invalidates the previous token), give each account a DISTINCT device/registration id at login and refresh the role via `mobile_identity_set` immediately before replaying as it.\n")
	if inv := apkStaticInventory(app); inv != "" {
		b.WriteString("\n" + inv)
	}
	b.WriteString("\nStatic/local analysis is SECONDARY — it corroborates and explains the live Burp evidence (use what is installed; degrade gracefully):\n")
	b.WriteString("- Bash: `jadx -d <out> <apk>` to decompile; `apktool d` for resources/manifest; `aapt2 dump badging/permissions`; `unzip -l`; `grep -r` over decompiled sources for secrets/URLs/crypto; `readelf`/checksec on lib/<abi>/*.so; `osv-scanner`/`trivy` for dependency CVEs; `trufflehog`/`gitleaks`/`semgrep` for secrets and insecure patterns.\n")
	b.WriteString("\nWork through OWASP MASVS v2 domains: STORAGE (shared_prefs/DB/cache/logs/backup), CRYPTO (hardcoded keys, weak primitives, Keystore), NETWORK (cleartext, TLS/trust managers, certificate pinning), PLATFORM (exported components, content providers, deep links, WebView/JS bridges, PendingIntent, screen/clipboard), AUTH (token/session lifecycle, biometric binding, API authorization/IDOR), CODE (third-party dependency CVEs, native PIE/RELRO/NX/canaries), RESILIENCE (root/emulator/debug detection, obfuscation, Play Integrity attestation), PRIVACY (identifiers, telemetry).\n")
	if len(scopeHosts) > 0 {
		b.WriteString("\nIN-SCOPE backend hosts (only test these over the network): " + strings.Join(scopeHosts, ", ") + ". Do not touch any other host.\n")
	} else {
		b.WriteString("\nNo backend hosts are in scope yet; perform static/local analysis of the APK only. Add scope before testing any live endpoint.\n")
	}
	b.WriteString("Record each confirmed issue as a finding with concrete evidence (file:line, manifest attribute, tool output). Redact secret values. Do not run destructive or exploitation payloads; this is a verification audit.\n")
	if e := strings.TrimSpace(extra); e != "" {
		if r := []rune(e); len(r) > 2000 {
			e = string(r[:2000]) + "…"
		}
		b.WriteString("\nAdditional operator objective: " + e + "\n")
	}
	return b.String()
}
