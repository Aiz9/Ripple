package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Aiz9/ripple/internal/db"
	"github.com/Aiz9/ripple/internal/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// Worker is an LLM work agent (docs §4.4): it claims ONE intent, completes it
// with real tools (Bash: kali tooling through the recording proxy), writes the
// FACTS it found back into the graph, and stops. It does NOT generate new
// directions (that is the planner's job) and does NOT keep exploring toward the
// goal on its own. Multiple workers run concurrently as goroutines.
// WebSearchOpts is the web-search backend selection the server pushes into each
// agent (planner/worker/main). Enabled=false leaves the web_search tool off.
// Backend is "ddgs" (no key), "brave-free" (BraveKey required), "tavily"
// (TavilyKey required), or "deepseek" (DeepSeek* required, filled from the
// active LLM profile). It maps directly onto agentcore.Options.
// Proxy is a dedicated egress proxy for the search request (http/https/socks5),
// independent of the traffic-recording MITM proxy — set it when the search endpoint
// is only reachable via a VPN/SOCKS proxy. Empty = direct.
//
// DeepSeek differs from the other search backends: it exposes no directly callable search API.
// Search is an internal Anthropic-compatible messages server tool (web_search_20250305),
// consuming one model call per search. Requests originate at DeepSeek, bypass local Proxy,
// and are not captured in recorded traffic.
type WebSearchOpts struct {
	Enabled   bool
	Backend   string
	BraveKey  string
	TavilyKey string
	Proxy     string
	// DeepSeek settings follow the active LLM profile (official DeepSeek Anthropic endpoint only),
	// rather than separate search configuration.
	DeepSeekBaseURL string
	DeepSeekAPIKey  string
	DeepSeekModel   string
}

type Worker struct {
	findingRecorder FindingRecorder
	prov            llm.Provider
	model           string
	workDir         string
	proxyAddr       string
	proxyCACert     string            // recording proxy's CA cert path (for WebFetch HTTPS verify)
	webSearch       WebSearchOpts     // web_search tool backend selection (off by default)
	tx              *transcript.Store // raw LLM conversation persistence (nil = off)
	window          int               // context window in tokens (for compaction)
	windowFn        func() int        // optional dynamic task-chain minimum
	maxTurns        int               // max agent turns per run (0 = unlimited)
	// runTimeout is the wall-clock budget for the main exploration of one intent
	// (0 = unlimited). When it fires, the run is cut and a settlement round is
	// forced so already-identified facts get written back instead of being lost.
	runTimeout time.Duration
	// extraTools are host-provided tools (e.g. traffic query, oast) appended to
	// the worker's graph write-back tools.
	extraTools []actool.CoreTool
	// injectConstraints resolves whether this task's operation constraints get
	// injected into the worker system prompt. Read per run so the settings toggle
	// takes effect without rebuilding the agent. nil = inject (default).
	injectConstraints func() bool
	// nonStreamingFn resolves whether this run uses the non-streaming (Complete)
	// path. Read per run so a profile/task toggle takes effect without rebuilding
	// the agent. nil = streaming (default).
	nonStreamingFn func() bool
	// noaEnabledFn resolves whether this run uses the experimental noa context-
	// compression mechanism. Read per run, like nonStreaming. nil = off (built-in
	// compaction).
	noaEnabledFn func() bool
	// maxTokensFn resolves the per-reply output cap in tokens, on the same
	// per-run basis. nil or 0 = send no cap and let the endpoint decide.
	maxTokensFn func() int
	// spawnValidation, if set, is handed to each run's ToolSet so a reported
	// finding spawns an independent validation intent. nil = disabled.
	spawnValidation func(findingID, findingNodeID int64, summary string)
}

// WorkerSessionID returns the stable transcript key used by a worker intent.
// Worker slots are reusable, so the intent id (rather than work#N) is the
// session identity. Keep this helper public so the Worker message API and UI
// can refer to exactly the conversation that will be resumed.
func WorkerSessionID(explorationID, intentID int64) string {
	return fmt.Sprintf("exp%d-worker-i%d", explorationID, intentID)
}

const workerChatMarkerPrefix = "<!-- ANDROIDLAB_WORKER_CHAT:"

func workerChatMarker(requestID string) string {
	return workerChatMarkerPrefix + requestID + " -->"
}

func hasWorkerChatMessage(messages []llm.Message, requestID string) bool {
	marker := workerChatMarker(requestID)
	for _, message := range messages {
		if message.Role == llm.RoleUser && strings.Contains(message.Text(), marker) {
			return true
		}
	}
	return false
}

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default). Read per
// run so a profile or task-chain toggle takes effect without rebuilding.
func (w *Worker) SetNonStreaming(fn func() bool) { w.nonStreamingFn = fn }

func (w *Worker) nonStreaming() bool { return w.nonStreamingFn != nil && w.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (w *Worker) SetNoaEnabled(fn func() bool) { w.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (w *Worker) SetMaxTokens(fn func() int) { w.maxTokensFn = fn }

func (w *Worker) maxTokens() int {
	if w.maxTokensFn == nil {
		return 0
	}
	return w.maxTokensFn()
}

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the worker system prompt. nil = inject (default).
func (w *Worker) SetConstraintInject(fn func() bool) { w.injectConstraints = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (w *Worker) wantConstraints() bool { return w.injectConstraints == nil || w.injectConstraints() }

// SetRunTimeout configures the per-intent wall-clock budget for the main
// exploration (0 = unlimited). When it fires, the SDK settlement phase still runs
// so facts are never lost to a timeout. Safe to call before Execute.
func (w *Worker) SetRunTimeout(run time.Duration) {
	w.runTimeout = run
}

// settleWrapUpPrompt is injected by the SDK settlement phase when a worker hits its
// turn/time budget: stop probing, write back what was found, then end with a
// plain-text one-liner (which becomes this run's displayed result).
const settleWrapUpPrompt = "Your budget is about to expire. Do not run further commands/probes. First persist every already identified unsaved result: insert_assets for assets, record_fact for conclusions/facts, report_finding for confirmed findings. Then output one standalone plain-text sentence summarizing your actions and key conclusions; this is displayed as the run result and is required."

func NewWorker(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int, extra ...actool.CoreTool) *Worker {
	return &Worker{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, extraTools: extra}
}

// defaultToolsExcept returns actool.DefaultTools() minus the named tools (by
// CoreTool.Name()). Used to trim SDK default tools an agent shouldn't have.
func defaultToolsExcept(exclude ...string) []actool.CoreTool {
	drop := make(map[string]bool, len(exclude))
	for _, n := range exclude {
		drop[n] = true
	}
	all := actool.DefaultTools()
	out := make([]actool.CoreTool, 0, len(all))
	for _, t := range all {
		if !drop[t.Name()] {
			out = append(out, t)
		}
	}
	return out
}

func (w *Worker) SetCompactionWindowResolver(fn func() int) { w.windowFn = fn }

func (w *Worker) compactionWindow() int {
	if w.windowFn != nil {
		return w.windowFn()
	}
	return w.window
}

// SetProxy configures the recording proxy address that workers route target
// traffic through, plus the CA cert path WebFetch trusts to verify HTTPS through
// that MITM proxy. Empty addr disables the hint.
func (w *Worker) SetProxy(addr, caCert string) { w.proxyAddr, w.proxyCACert = addr, caCert }

// SetSpawnValidation wires the per-finding validation spawner (see Worker.spawnValidation).
func (w *Worker) SetSpawnValidation(fn func(findingID, findingNodeID int64, summary string)) {
	w.spawnValidation = fn
}

// SetWebSearch selects the web_search backend for this worker (off by default).
func (w *Worker) SetWebSearch(o WebSearchOpts) { w.webSearch = o }

// proxyEnv builds the Bash-subprocess env that routes child-command HTTP through
// the egress proxy (the recording MITM when capture is on, or the global proxy
// directly when it is off) and, only when a MITM CA is present, makes the common
// toolchain trust it — so tools need no manual -x/--proxy/-k. Each ecosystem reads
// a different CA var (verified empirically): SSL_CERT_FILE→curl/urllib/Go/openssl,
// REQUESTS_CA_BUNDLE→python requests (it ignores SSL_CERT_FILE), CURL_CA_BUNDLE→curl,
// GIT_SSL_CAINFO→git, NODE_EXTRA_CA_CERTS→node; NODE_USE_ENV_PROXY makes Node 24+
// honor the proxy vars. ALL_PROXY is set too so a socks5 egress proxy (which curl
// only reads from ALL_PROXY, not HTTP(S)_PROXY) works in the capture-off path.
// Empty proxyAddr → nil (direct, unchanged env).
func proxyEnv(proxyAddr, caCert string) []string {
	if proxyAddr == "" {
		return nil
	}
	env := []string{
		"HTTP_PROXY=" + proxyAddr, "HTTPS_PROXY=" + proxyAddr,
		"http_proxy=" + proxyAddr, "https_proxy=" + proxyAddr,
		"ALL_PROXY=" + proxyAddr, "all_proxy=" + proxyAddr, // socks5 egress: curl reads only this
		"NODE_USE_ENV_PROXY=1", // Node 24+: honor HTTP(S)_PROXY in built-in fetch/http
	}
	if caCert != "" {
		env = append(env,
			"SSL_CERT_FILE="+caCert,
			"CURL_CA_BUNDLE="+caCert,
			"REQUESTS_CA_BUNDLE="+caCert,
			"GIT_SSL_CAINFO="+caCert,
			"NODE_EXTRA_CA_CERTS="+caCert,
		)
	}
	return env
}

// workerDefaultTmpl is the built-in editable system-prompt body (section [A]),
// seeded into agent_prompts. Traffic-tool and artifact-output rules remain code-owned
// are NOT here — they are code-owned and appended by workerSystem after rendering
// sections [B]/[C], so editing the DB body cannot remove them.
const workerDefaultTmpl = `You are the "Executor" (work agent) of an authorized penetration testing system. You are assigned ONE INTENT (a single-direction exploration task). Your sole responsibility: **Execute this intent, record findings/facts back to the knowledge graph, and then stop.**

**Boundaries (Red Lines)**:
1. **Focus solely on your assigned intent**. If you observe promising leads outside this intent during exploration (e.g., leaked paths in errors, potential pivot points, suspected entry points for another chain), mention them briefly in the fact summary for the planner.
2. Initial resistance (payload filtered, 404, blind injection with no echo) does NOT mean the path is exhausted—attempt standard bypass techniques before concluding.
3. Operate strictly within authorized scope. If [Operational Constraints] are attached at the top of the prompt, they are highest-priority red lines: self-check every command/probe before executing, and do not execute if prohibited. The platform hard-blocks any request to a deletion endpoint (/delete /remove /unlink /erase /destroy, any method) as a policy red line — never attempt one or try to reword it; test the destructive capability by other means (e.g. authorization on the create/read route) and record the delete path as blocked.

**Coverage within your intent (exhaustive, not illustrative)**: If your intent names a vulnerability class or a surface (authz / IDOR / BOLA / BFLA, injection, broken access control, business logic, sensitive-data exposure…), test EVERY in-scope instance, not a single example. First inventory the real surface — mobile_traffic_history / traffic_search for the app's live API (the top-priority source), plus list_assets and endpoints already discovered — then exercise each endpoint/route/parameter/HTTP method in scope. For authorization/IDOR/BOLA, replay each object or endpoint with BOTH supplied test identities (mobile_traffic_replay) and compare the responses; a 2xx alone is not proof. Do not stop at same-identity A-vs-B swaps: if the app or backend exposes more than one login/token path (app, convergent/third-party, SSO, account-link), mint a token from EACH and replay it across every API version family (legacy/v1 AND v2) — a token minted for one audience accepted on another (e.g. on a fund-transfer or QR-payment route) is a critical authorization-boundary bypass. Test every enumerated endpoint family at least once, not only the routes the app itself calls. Before any authenticated login to a shared test account, acquire_live_lease("account:<id>") so you do not evict a peer worker's session; release_live_lease when done. For business-logic intents, walk the complete workflow end-to-end (e.g. transfer: amount → beneficiary → confirm → OTP/step-up binding → replay/duplicate). Record a result for each instance. When several instances share ONE root cause and remediation, consolidate them into a SINGLE finding/fact whose evidence lists every affected endpoint/parameter/role; report separately only when root cause, impact, or fix genuinely differ. In your closing summary, state which parts of the surface you covered and which remain, so the planner can dispatch the rest.

**Persist observations immediately** (only data written to the graph counts; write results as you discover them, do not wait until step limits are reached):
- **New assets/resources → insert_assets (Asset Graph)**: Subdomains, services, endpoints, fingerprints, credentials, and assets themselves. Only register assets here; do not write conclusions here.
- **Exploration conclusions/facts → record_fact (Exploration Graph, pass intent_id)**: Summarize multiple observations into ONE comprehensive fact (concise summary + detailed expansion). Default to writing a single consolidated fact; only use facts array for completely independent conclusions. Record incremental discoveries only. Provide concise evidence (command + 1-2 lines of output) and confidence (observed = directly witnessed / inferred = deduced from behavior).
- **Confirmed vulnerabilities → report_finding (Exploration Graph, with PoC, pass intent_id)**: USE ONLY WHEN you have actually triggered the vulnerability this run and obtained reproducible evidence (request/response or command output). Never report unverified CVE matches, "parameters look vulnerable", or theoretical deductions without actual reproduction. If unverified but suspicious, record an inferred fact via record_fact for the planner.
- **Coverage → record_test_coverage**: one row per surface × risk you assessed, including clean ones. Every candidate you open ends in exactly ONE explicit state: reported (finding filed), no_issue_found, ruled_out (name the SPECIFIC control, at a location, that runs on every attacker-reachable path), needs_follow_up (plausible, unconfirmed, no such control found — say what would prove it), or blocked (state the blocker). "I moved on" is not a closure state. Missing information (no caller found, endpoint unreachable, second account missing) is NOT proof of safety: needs_follow_up or blocked, never ruled_out. Check list_test_coverage first and move an existing row instead of re-testing closed ground.

**Before report_finding — counterevidence pass**: argue the strongest case AGAINST the finding (intended behaviour? your own session/setup? enforced server-side after all?), check it, and put the result in counterevidence; set confidence honestly. Severity reflects only the impact your PoC demonstrated, not theoretical follow-ons. If later testing disproves a finding you or another worker filed, withdraw_finding it. If your testing contradicts the shared threat model (a "trusted" boundary is reachable, an unknown role/host/endpoint), amend_threat_model.

After completing the intent, provide a one-sentence summary of what was performed and what facts were recorded.`

// workerTrafficBlock is section [B], injected only when traffic tools are available.
// traffic capture (recording) is on — i.e. the traffic_* tools actually exist.
// Gated on recording, NOT on the egress proxy: a global proxy with capture off
// routes traffic but records nothing, so the tools would not be there. Not stored,
// not editable.
func workerTrafficBlock(recording bool) string {
	if !recording {
		return ""
	}
	return "\n\n**Traffic Tools**:\n- traffic_search / traffic_get / traffic_blob: Check previous responses and revisit accessed resources. **Check traffic first; do not repeatedly curl the same URL**. traffic_search **requires a host**, returns lightweight indexes (id/method/url/status/resp_len, no response body) by default; increase limit if needed. Use body_contains for full-text search across request/response headers and bodies (at least 3 characters). Use traffic_get(id) for full text; oversized bodies marked as @blob sha256:<hash> can be read in chunks with traffic_blob(hash)."
}

// artifactSpec is the code-owned, uneditable section [C] appended to every
// pentest agent's prompt — intermediate artifacts must land in the shared work
// dir, never /tmp. Guaranteed present regardless of how the DB body is edited.
func artifactSpec(dir string) string {
	return "\n\n**Intermediate Artifact Specification**: All intermediate artifacts (scripts, payloads, captured responses, temporary data) **must be written to this task working directory " + dir + "** (relative paths write here, or use this absolute path). **Do not write to /tmp or use other absolute paths.**"
}

// workerArtifactSpec is Worker section [C]; its per-intent directory is created first
// by the engine (ensureRunDir), so it just writes relative paths there — no manual
// mkdir, no cross-worker name collisions.
func workerArtifactSpec(runDir string) string {
	return "\n\n**Intermediate Artifact Specification**: All intermediate artifacts (scripts, payloads, captured responses, temporary data) **must be written to this intent working directory " + runDir + "** (already created; write relative paths here directly without manual mkdir). **Do not write to /tmp or use other absolute paths.**"
}

// ensureRunDir builds and creates an agent's working directory under base:
// <base>/tasks/<taskID> for planner/main; <base>/tasks/<taskID>/i<intentID> for a
// worker (intentID<=0 → task dir only). The "tasks/" segment groups per-task dirs
// symmetrically with the chat agent's "sessions/<sessionID>". Best-effort mkdir — on
// failure, writes fail the same way an unwritable CWD would.
func ensureRunDir(base string, taskID, intentID int64) string {
	dir := filepath.Join(base, "tasks", strconv.FormatInt(taskID, 10))
	if intentID > 0 {
		dir = filepath.Join(dir, "i"+strconv.FormatInt(intentID, 10))
	}
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// cmdOutDir is the SDK large-tool-output spill dir under an agent's run dir.
func cmdOutDir(dir string) string { return filepath.Join(dir, "cmd-output") }

func workerSystem(proxyAddr, caCert, dataDir, runDir string) string {
	body := renderSystem("worker", workerDefaultTmpl, WorkerVars{ProxyAddr: proxyAddr, DataDir: dataDir, Now: nowStr()})
	// caCert is present only when the recording MITM is on, which is exactly when
	// the traffic_* tools are registered — so it gates the traffic-tool note.
	// Optional finding guidance is added for every role after tool resolution.
	return body + workerTrafficBlock(caCert != "") + workerArtifactSpec(runDir)
}

// renderIntentTask formats the claimed intent for the worker's launch USER message:
// the intent is the worker's whole job. It used to live in the system prompt; it now
// rides in the first user turn (together with the situational overview) so the system
// prompt stays static/role-only — same move as the planner's situational block.
// intentAssetIDs pulls the intent's target asset ids out of its payload
// (planner's add_intent stores them as a numeric asset_ids array). nil on absence
// or malformed payload.
func intentAssetIDs(intent *db.Node) []int64 {
	if intent == nil {
		return nil
	}
	var p struct {
		AssetIDs []int64 `json:"asset_ids"`
	}
	if err := json.Unmarshal(intent.Payload, &p); err != nil {
		return nil
	}
	return p.AssetIDs
}

func renderIntentTask(intent *db.Node) string {
	out := fmt.Sprintf("\n\n[Your claimed intent (the only assignment for this run: do only this, produce facts, then stop)]:\n%s\nIntent ID: %d (pass to record_fact / report_finding / record_test_coverage)", string(intent.Payload), intent.ID)
	var p struct {
		Skills []string `json:"skills"`
	}
	if json.Unmarshal(intent.Payload, &p) == nil && len(p.Skills) > 0 {
		out += "\nBefore testing, load these skills with the Skill tool and follow them: " + strings.Join(p.Skills, ", ")
	}
	return out
}

// renderWorkerGraphOverview folds the global situational snapshot into the worker's
// launch USER message for AWARENESS ONLY. The framing is deliberately strong: the overview
// must NOT widen the worker's job — it still does only its assigned intent. Its sole
// purpose is letting the worker read context (existing facts/assets/hints)
// so it avoids redundant work and doesn't re-derive what others already found.
func renderWorkerGraphOverview(data map[string]any) string {
	// Coverage helps planners decide which types need work or scope expansion. Workers must
	// execute only their claimed intent rather than chase uncovered assets; remove coverage from
	// this Worker-specific map without affecting the planner's data.
	delete(data, "coverage")
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back silently: the worker just won't have the global context
	}
	return "\n\n[Global exploration state (read-only, to place your intent in context)]:\n" +
		"The following is the current task-wide overview: use others' discoveries to avoid duplicate work and understand how your intent relates to the whole task.\n" +
		"Think broadly while exploring this intent, but do not execute other intents (the planner assigns those to other Workers). Always record valuable connections as facts for the planner: cross-asset relationships, possible entry points to another exploit chain, or suspicious global patterns. These are important outputs. Prefer reporting an extra lead for the planner to assess over withholding it.\n" +
		string(b)
}

// Execute runs one intent. hooks (the per-task Guard) gates every tool call; may
// be nil. emit, if non-nil, receives one ActivityRecord per execution step.
// notifyFinding, if non-nil, is called (intentID, summary) when this worker writes
// a finding (report_finding) so the task's planner wakes mid-flight — with context
// on which intent found what — instead of waiting for the worker to finish.
// Returns the terminal reason (so the engine can distinguish completed vs
// max_turns) and a per-kind breakdown of what was written back (so an intent that
// explored but persisted nothing isn't mistaken for done, and the engine can log
// facts/assets/findings separately instead of lumping them under "facts").
func (w *Worker) Execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string)) (harness.TerminalReason, WriteCounts, error) {
	return w.execute(ctx, name, taskID, as, ts, intent, hooks, emit, enr, notifyFinding, "", "")
}

// ExecuteWithMessage runs the next turn in the same intent conversation with a
// human-authored message. The HTTP handler does not edit the transcript;
// agentcore records the message as a normal user turn when this Worker starts.
// This keeps Worker continuation identical to the regular agent chat flow.
func (w *Worker) ExecuteWithMessage(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string), requestID, message string) (harness.TerminalReason, WriteCounts, error) {
	return w.execute(ctx, name, taskID, as, ts, intent, hooks, emit, enr, notifyFinding, strings.TrimSpace(requestID), strings.TrimSpace(message))
}

func (w *Worker) execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string), requestID, message string) (harness.TerminalReason, WriteCounts, error) {
	tsx := NewToolSet(ts, name)
	defer tsx.ReleaseLeases() // free any live-work leases when this run ends (TTL is only the crash safety net)
	tsx.SetFindingRecorder(w.findingRecorder)
	tsx.SetTaskID(taskID)
	coverageEnabled := as == nil || as.CoverageEnabled(taskID)
	tsx.SetCoverageEnabled(coverageEnabled)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetOwnerNode(intent.ID)               // assets this worker discovers anchor to its intent → visible to the task
	tsx.SetEnrich(enr)                        // async DNS/HTTP auto-completion for assets this worker writes
	tsx.SetNotifyFinding(notifyFinding)       // report_finding immediately wakes planning with intent and finding information.
	tsx.SetSpawnValidation(w.spawnValidation) // report_finding auto-spawns an independent validation intent (recursion-guarded).
	// base = built-in worker tools ∪ host tools (traffic) ∪ default tools (incl. Bash);
	// then augment with the agent's visible skills/MCP. During the SDK settlement
	// phase, Bash is hidden via Settlement.DisabledTools (no local gating needed).
	base := append(tsx.WorkerTools(), w.extraTools...)
	// Exclude MultiEdit/Glob/Grep from Workers: Edit handles focused edits; Bash grep/find handles
	// search. Keep SDK Read/Write/Edit/LS/Bash/Sleep while narrowing low-value tool choices.
	base = append(base, defaultToolsExcept("MultiEdit", "Glob", "Grep")...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts), IntentID: intent.ID})
	tools, def, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()

	// The intent is the Worker's invariant assignment across the entire run. Put it, startup
	// instructions, and raw anchored assets in the system prompt, rebuilt per run and never compacted.
	// Long runs and resumed transcripts therefore retain the mandate even if the first message is gone.
	// This sacrifices cross-intent system-cache reuse to avoid the more serious loss of assignment.
	// Planner state stays in user input because planners create intents and have no single mandate.
	// Worker global overview alone stays in initial user input; it may become stale or be compacted.
	// Engine-created intent workspace: <workDir>/tasks/<taskID>/i<intentID>.
	runDir := ensureRunDir(w.workDir, taskID, intent.ID)
	// The run-wide intent is not the current tool action. Do not forward it or
	// inherit a parent run's background into the action reviewer.
	ctx = intercept.WithReviewContext(ctx, runDir, intercept.ReviewBackground{})
	overview := renderWorkerGraphOverview(tsx.graphOverviewData())
	sysBody := workerSystem(w.proxyAddr, w.proxyCACert, w.workDir, runDir)
	if w.wantConstraints() {
		sysBody += constraintBlock(ts) // Inject operational constraints into the system prompt for strict Worker enforcement.
	}
	sysBody += threatModelBlock(ts, "worker")
	// Append intent, anchored assets, then startup instructions to system, like constraintBlock.
	sysBody += renderIntentTask(intent)
	if as != nil {
		if ids := intentAssetIDs(intent); len(ids) > 0 {
			if assets, err := as.GetByIDs(ids); err == nil && len(assets) > 0 {
				if b, err := json.Marshal(assets); err == nil {
					sysBody += "\n\nTarget assets corresponding to this intent's asset_ids:\n" + string(b)
				}
				// Explicit intent targets automatically enter task scope at the same conservative granularity
				// as insertAssets. ON CONFLICT DO NOTHING and uq_task_scope prevent duplicates;
				// reruns/retries are idempotent.
				// Do not accumulate coverage-denominator scope when asset coverage is disabled.
				if coverageEnabled {
					for _, a := range assets {
						_ = as.AddAutoScope(taskID, a.Type, a.Domain, a.URL, a.IP)
					}
				}
			}
		}
	}
	sysBody += "\n\nExecute only the above intent, producing facts, assets, and findings; stop when done."
	system, boundary := deferredSystem(sysBody, def)
	// A ctx-injected task deadline clamps this run's wall-clock budget and selects settlement wording.
	tc := taskClockFrom(ctx)
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, w.runTimeout)
	settle := wrapupSettlement("worker", []string{"Bash"})
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("worker", []string{"Bash"}, clamped)
	}
	opts := agentcore.Options{
		Provider:        w.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		// WebFetch records HTTP like curl through the proxy; load its CA to validate MITM-signed HTTPS
		// normally rather than disabling verification. Empty proxy means direct.
		EnableWebFetch: true,
		WebFetchProxy:  w.proxyAddr,
		WebFetchCACert: w.proxyCACert,
		// Optional web search: ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is separate http/https/socks5 egress, unrelated to recording MITM; empty is direct.
		EnableWebSearch:       w.webSearch.Enabled,
		WebSearchBackend:      w.webSearch.Backend,
		BraveSearchAPIKey:     w.webSearch.BraveKey,
		TavilySearchAPIKey:    w.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: w.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  w.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   w.webSearch.DeepSeekModel,
		WebSearchProxy:        w.webSearch.Proxy,
		// Bash HTTP subprocesses use the recording proxy and trust its CA, without requiring -x/-k.
		BashEnv:    proxyEnv(w.proxyAddr, w.proxyCACert),
		WorkingDir: runDir,
		MaxTurns:   w.maxTurns, // 0 = unlimited (configurable in agent management)
		// Wall-clock budget checked at round boundaries; 0 is unlimited. Clamp to the minimum of own
		// budget and remaining task deadline for task-expiry settlement (taskclock.go).
		MaxDuration: maxDur,
		// At turn/time limit the SDK settles with Bash hidden and persists identified results.
		// With a clamped deadline, PromptByReason selects task-timeout wording for time expiry,
		// per-run wording for earlier step exhaustion. Unclamped runs always use per-run wording.
		Settlement: settle,
		// large tool output spills to cmd-output/ with a head + pointer (SDK tool.Capture);
		// Full output persists on disk; use SDK truncation default (30000 characters).
		ToolOutputDir: cmdOutDir(runDir),
		Compaction:    compactionConfig(w.compactionWindow()), // long tool-heavy runs stay within the window
		Todos:         actool.NewTodoStore(),                  // Session-local TodoWrite planning scratchpad, discarded on exit.
		NonStreaming:  w.nonStreaming(),                       // Non-streaming profiles use Provider.Complete.
		MaxTokens:     w.maxTokens(),                          // 0 omits the output limit, leaving the server default.
	}
	if hooks != nil { // typed-nil guard: only set when concrete (avoids harness panic)
		opts.Hooks = hooks
	}
	if w.tx != nil { // persist raw LLM conversation; one file per worked intent
		opts.Transcript = w.tx
		opts.SessionID = WorkerSessionID(ts.ID(), intent.ID)
	}
	intentID := intent.ID
	emitWrap := func(r db.Activity) {
		if emit != nil {
			r.NodeID, r.Worker = &intentID, name
			emit(r)
		}
	}
	// Intent/startup instructions/anchored assets are already in system (sysBody above).
	// This startup user message carries only the degradable global overview, safe to compact.
	// If overview marshaling unexpectedly fails, supply startup text to avoid an empty first user turn.
	input := overview
	if strings.TrimSpace(input) == "" {
		input = "Execute only the intent assigned in the system prompt, producing facts, assets, and findings; stop when done."
	}

	// Experimental noa compaction persists archives under <workDir>/noa/<SessionID>.
	noaSession := WorkerSessionID(ts.ID(), intent.ID)
	enableNoa(&opts, w.noaEnabledFn, w.workDir, noaSession, noaWarn(noaSession))
	ctx = attachSideCapture(ctx, &opts)
	s := agentcore.NewSession(opts)
	defer s.Close() // release the session's background-task manager (temp dir + processes)

	// Resume prior conversation if this intent was paused/blocked/exhausted and is
	// being re-run. The transcript ID is deterministic per intent, so if a prior
	// session exists the worker continues from where it left off instead of
	// restarting from scratch.
	alreadyRecorded := false
	if w.tx != nil {
		_ = s.Resume(opts.SessionID)
		alreadyRecorded = requestID != "" && hasWorkerChatMessage(s.Messages(), requestID)
		if len(s.Messages()) > 0 && message == "" {
			seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
			input = "Continue execution."
		} else if len(s.Messages()) > 0 {
			seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
		}
	}
	if message != "" {
		if alreadyRecorded {
			input = "Continue the new intent from the previous human conversation input. Do not repeat completed actions."
		} else if len(s.Messages()) > 0 {
			input = workerChatMarker(requestID) + "\n[New intent from human conversation input]\n" + message +
				"\n\nExecute this human instruction immediately, then decide from context whether the original task needs to continue."
		} else {
			input += "\n\n" + workerChatMarker(requestID) + "\n[New intent from human conversation input]\n" + message +
				"\n\nPrioritize this human instruction."
		}
	}

	// Budgets + settlement are owned by the SDK (MaxTurns/MaxDuration + Settlement):
	// on hit it runs a wrap-up turn and finishes with ReasonMaxTurns/ReasonTimeout.
	// MaxDuration now interrupts an in-flight tool at the wall-clock deadline and
	// enters the wrap-up phase on the live ctx, so a run whose tool overran the budget
	// still settles (no external hard-timeout backstop needed). ctx itself carries only
	// pause / planner kill / shutdown, which the engine distinguishes and re-queues/stops.
	_, reason, err := captureRunSession(ctx, s, input, emitWrap)
	return reason, tsx.Writes(), err
}
