package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Aiz9/ripple/internal/db"
	"github.com/Aiz9/ripple/internal/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	findingRecorder   FindingRecorder
	prov              llm.Provider
	model             string
	tx                *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window            int                                    // context window in tokens (for compaction)
	windowFn          func() int                             // optional dynamic task-chain minimum
	maxTurns          int                                    // max agent turns per run (0 = unlimited)
	killWork          func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork         func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	proxyAddr         string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert       string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch         WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir           string                                 // shared work dir (surfaced in prompt as artifact-output target)
	injectConstraints func() bool                            // resolver: inject task operation constraints into system prompt? (nil = yes)
	nonStreamingFn    func() bool                            // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn      func() bool                            // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn       func() int                             // resolver: per-reply output cap (nil/0 = send no cap)
	compactor         *Compactor                             // cold-node compaction (§7); nil = disabled

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

func (p *Planner) SetCompactionWindowResolver(fn func() int) { p.windowFn = fn }

// SetCompactor wires the cold-node compactor (cold-digest §7). Called each
// planner wake-up to advance the round counter, maintain cold stamps, and
// (off the hot path) fold cold nodes into digests. nil = feature disabled.
func (p *Planner) SetCompactor(c *Compactor) { p.compactor = c }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (p *Planner) SetNonStreaming(fn func() bool) { p.nonStreamingFn = fn }

func (p *Planner) nonStreaming() bool { return p.nonStreamingFn != nil && p.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (p *Planner) SetNoaEnabled(fn func() bool) { p.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (p *Planner) SetMaxTokens(fn func() int) { p.maxTokensFn = fn }

func (p *Planner) maxTokens() int {
	if p.maxTokensFn == nil {
		return 0
	}
	return p.maxTokensFn()
}

func (p *Planner) compactionWindow() int {
	if p.windowFn != nil {
		return p.windowFn()
	}
	return p.window
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the planner system prompt. Read per round so the
// settings toggle takes effect without rebuilding the agent. nil = inject (default).
func (p *Planner) SetConstraintInject(fn func() bool) { p.injectConstraints = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (p *Planner) wantConstraints() bool { return p.injectConstraints == nil || p.injectConstraints() }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Your planning todo list (preserved across wakeups, written last round)]:\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Proceed from this list: dispatch only the next steps whose prerequisites are complete or whose required facts exist. Update TodoWrite, marking fact-satisfied steps completed. Do not redispatch steps already pending/in_progress.")
	return b.String()
}

// TriggerEvent describes what concretely caused this planning round to fire, so
// the planner looks first at the actual change instead of re-scanning the whole
// overview. Kind:
//
//	"done"    — a worker finished intent IntentID (its output conclusion is fetched).
//	"finding" -- Worker reported a finding on IntentID (Detail = summary).
//	"goal" -- human added one or more goals via main-agent set_goals in a
//	            single call (Goals holds the added goal texts; batching is supported).
//	"goal_deleted" -- human removed a goal in overview management (Detail = old text).
//	"goal_edited" -- human changed a goal in overview management (OldGoal -> NewGoal).
//	"cancelled" -- human deleted IntentID (Detail = deletion reason). The intent is
//	            stopped (not deleted) and the reason is attached to it as a fact.
type TriggerEvent struct {
	Kind     string
	IntentID int64
	Detail   string
	Summary  string   // For cancelled: summary captured before deletion, since hard deletion removes the node.
	Goals    []string // For goal: texts added by this set_goals call (one or many).
	OldGoal  string   // For goal_edited: previous goal text.
	NewGoal  string   // For goal_edited: updated goal text.
	Hints    []string // For hint: texts added by this add_hint call (one or many).
}

// renderTriggers spells out the change(s) that fired this round: for a finished
// worker — which intent + its output conclusion; for a finding — which intent +
// what was found. Empty for time/heartbeat wakes. Reads the store (best-effort;
// a blank field never blocks the round).
func renderTriggers(ts *db.ExplorationStore, evs []TriggerEvent) string {
	if len(evs) == 0 || ts == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Actual changes triggering this round (read before deciding whether to add directions)]:")
	for _, ev := range evs {
		switch ev.Kind {
		case "goal":
			if len(ev.Goals) == 1 {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added one goal: %s -- add a direction for this new goal if no corresponding intent exists.", ev.Goals[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added %d goals: %s -- add a direction for each new goal without a corresponding intent.", len(ev.Goals), strings.Join(ev.Goals, "; ")))
			}
		case "hint":
			if len(ev.Hints) == 1 {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added a strategic hint: %s -- attached to the exploration graph; adjust/add a direction if no corresponding intent exists.", ev.Hints[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- The human (main agent) added %d strategic hints: %s -- all attached to the graph; adjust/add directions for each.", len(ev.Hints), strings.Join(ev.Hints, "; ")))
			}
		case "goal_deleted":
			b.WriteString(fmt.Sprintf("\n- The human deleted this goal: %s -- reassess remaining goals/directions; no intent is needed for the removed goal.", ev.Detail))
		case "goal_edited":
			b.WriteString(fmt.Sprintf("\n- The human changed a goal from '%s' to '%s' -- adjust directions for the new goal and stop dispatching obsolete directions.", ev.OldGoal, ev.NewGoal))
		case "finding":
			b.WriteString(fmt.Sprintf("\n- The worker for intent #%d (%s) reported a finding: %s", ev.IntentID, intentSummary(ts, ev.IntentID), ev.Detail))
		case "cancelled":
			// Prefer Summary captured at deletion; hard deletion makes intentSummary lookup impossible.
			sm := ev.Summary
			if sm == "" {
				sm = intentSummary(ts, ev.IntentID)
			}
			b.WriteString(fmt.Sprintf("\n- The user deleted intent #%d, content: %s, reason: %s. It will no longer execute; replan accordingly.", ev.IntentID, sm, ev.Detail))
		default: // "done"
			b.WriteString(fmt.Sprintf("\n- The worker for intent #%d (%s) finished with conclusion: %s", ev.IntentID, intentSummary(ts, ev.IntentID), workerOutput(ts, ev.IntentID)))
			if fids := factIDsYielded(ts, ev.IntentID); fids != "" {
				b.WriteString(fmt.Sprintf("; new fact IDs from this intent: %s ", fids))
			}
		}
	}
	b.WriteString("\n(Full details available via node_detail / get_worker_output / list_findings.)")
	return b.String()
}

// factIDsYielded lists the fact ids an intent produced this run as "#12, #15", so the
// planner can jump straight to the round's incremental facts. Empty (best-effort) when
// the intent yielded no facts or the lookup fails.
func factIDsYielded(ts *db.ExplorationStore, id int64) string {
	ids, err := ts.FactsYielded(id)
	if err != nil || len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, fid := range ids {
		parts[i] = fmt.Sprintf("#%d", fid)
	}
	return strings.Join(parts, ", ")
}

// intentSummary reads an intent node's one-line summary (best-effort, "?" on miss).
func intentSummary(ts *db.ExplorationStore, id int64) string {
	n, err := ts.GetNode(id)
	if err != nil || n == nil {
		return "?"
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok && s != "" {
			return s
		}
	}
	return "?"
}

// workerOutput returns the finished worker's conclusion for an intent — the last
// 'result' (else 'text') activity's full detail, truncated. Same source get_worker_output uses.
func workerOutput(ts *db.ExplorationStore, id int64) string {
	acts, _, err := ts.ActivityList(&id, 0, 1000)
	if err != nil {
		return "(failed to retrieve output)"
	}
	var pick *db.Activity
	for i := range acts {
		if acts[i].Kind == "result" {
			pick = &acts[i]
		} else if acts[i].Kind == "text" && pick == nil {
			pick = &acts[i]
		}
	}
	if pick == nil {
		return "(no output recorded for this work)"
	}
	out, _ := ts.ActivityDetail(pick.ID)
	if out == "" {
		out = pick.Summary
	}
	return truncOutput(out, 800)
}

// truncOutput caps a worker-output blob so the trigger context doesn't bloat the
// system prompt every round; full text is one get_worker_output call away.
func truncOutput(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + " … (truncated; see get_worker_output for full text)"
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n[Current round situation (pre-fetched graph_overview, equivalent to calling that tool; use node_detail/list_facts for details)]:\n" + string(b)
}

// plannerDefaultTmpl is the built-in editable planner body (section [A]),
// seeded into agent_prompts. Goal is {{.Goal}}; the artifact-output contract
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `You are the "Planner" of an authorized penetration testing system, awakened whenever the graph changes. Role: Read situation → Assess goals → **Add exploration intents only when there are uncovered new directions**. You are a planner, not an executor: all outputs this round must be either [generating/clarifying intents] or [evaluating goals], never executing the work in the plan.

Task goal: {{.Goal}}

**How many intents to produce this round (consider this first)**:
- **Hard baseline (highest priority)**: Whenever [goals are not met] AND [no intents are currently open or running] (frontier_open=0 and running_intents is empty), this round MUST produce at least one intent advancing toward goals. If there is no running work to wait for and no directions queued, producing 0 intents = task stalls. Even if all known directions are in recent_done, you must open a new direction or dispatch a follow-up based on the done/exhausted/blocked assessments below.
- Outside the hard baseline, **producing 0 intents is a normal result with valid justification** (not a "fewer is safer" default):
  1) **Already covered**: All directions you identified are currently handled by open/running intents (re-generating existing intents with different wording is a serious error).
  2) **Waiting on dependencies**: The next step depends on output from currently running work that is not yet ready (forcing an intent now causes downstream workers to idle without prerequisites; wait for the next graph update).
- Conversely: If there is an uncovered new direction that does not depend on running work, or goals are unmet and unexplored scope remains, dispatch it—do not treat 0 intents as a lazy default.

**Decision process on each wake-up**:

1. **Complete situation is attached below** (equivalent to graph_overview return): task (original title + goal/root node), asset counts, goals + status, open/running/recent_done intents, sites_without_endpoints, facts (count of exploration facts, distinct from vulnerabilities), recent_facts ({id, summary, confidence?}).
   - **Scope**: Exploration nodes (goals/intents/facts/findings) belong only to this task; **asset graph is globally shared** (ignore assets not related to this task).
   - **Lineage**: Each intent includes parents (upstream nodes derived from) and yields (downstream facts/findings produced); recent_facts includes from_intent. Use this to understand which facts came from which direction and whether they synthesize into new directions.
   - **Negative/uncertain observations** ("port closed / not injectable" in recent_facts) are worker observations, not absolute conclusions. Check node_detail(id) for evidence before accepting. Strong evidence + observed confidence with exhausted methods = direction temporarily closed. Missing evidence or inferred confidence = not yet determined; if in scope and uncovered, dispatch one recheck intent (at most once per negative direction).
   - **Detailed tools as needed**: list_facts, list_findings, node_detail(id), list_assets, asset_neighbors.

2. **Assess goals (Core responsibility)**: goals field contains goals and statuses. For unmet goals proven by a finding/fact, call prove_goal(goal_id, evidence_id, reason) to mark met. **When you mark the very last remaining goal, the system automatically determines the entire task is complete**.
   - Quantitative verification: For quantifiable conditions (coverage X%, N flags, specific privilege), verify actual metrics in graph_overview before prove_goal. Never mark met early.
   - Exhaustive-coverage goals: when a goal/constraint says to check a vulnerability class across ALL endpoints/parameters/roles/workflows, do NOT prove_goal until the surface was enumerated and every instance is either tested or explicitly justified as not-applicable/out-of-scope with evidence. One example finding does not satisfy an "across all …" goal.

3. **(Optional, initial phase only, ultra-lightweight) Exploratory probe**: Only when the graph has almost no facts and the situation is unclear, perform minimal read-only probes with Bash (e.g., 1–2 curls for fingerprinting). The ONLY valid output is a more precise intent description—never vulnerability exploitation or endpoint fuzzing (those are worker tasks).

4. **Decide new directions**:
   - Already covered by open/running → Do not generate.
   - Appeared in recent_done → Check state:
     · **done**: Covered → do not re-dispatch identically; only re-dispatch if material new facts/parameters/attack vectors emerge.
     · **exhausted / blocked**: Check get_worker_trace / get_worker_output to see where it stopped and adjust.
   - Uncovered new direction → Generate.
   - **Exhaustive-coverage goals** (e.g. "IDOR across all account/transaction/beneficiary/statement functions", "injection across all parameters", "BOLA on every endpoint"): here breadth across the surface IS the objective and overrides depth-over-breadth. First ensure the real surface is enumerated (captured traffic, list_assets, discovered endpoints); if it is not, dispatch an enumeration/discovery intent first. Then dispatch SYSTEMATIC coverage intents that partition the surface (per endpoint-group / per role / per parameter-set), and for authz/IDOR include both supplied test identities. Coverage intents aimed at DIFFERENT endpoints/roles/parameters are NOT duplicates even when similarly worded — do not suppress them as "already covered". Over successive rounds, keep dispatching until the surface is covered.
   - Depth over breadth (default, non-coverage goals): High-value leads (RCE, privilege escalation, data exfiltration) should be pursued deeply rather than shallowly across all assets.
   - Maintain diverse attack vectors (e.g., file upload vs. auth bypass).
   - Serial chains: Dispatch step-by-step using TodoWrite, not in parallel.
   - **Threat model first**: if the situation says there is no threat model, the first testing round dispatches ONE threat-modelling intent (vuln_class=threat-model) whose worker saves it; vulnerability intents follow. Use the threat model's trust boundaries and severity calibration to rank directions.
   - **Close every lead**: every needs_follow_up row in the coverage ledger is owed work — dispatch an intent (vuln_class=validation, same surface) that moves it to its real outcome. Leave a row only when it is genuinely blocked, recorded as blocked with the blocker. Use list_test_coverage to find surfaces enumerated but never tested.
   - **Disproved findings**: when evidence shows a finding is not a vulnerability, withdraw_finding it (never leave it on file).
   - **Finding validation is automatic**: each reported finding already spawns its own independent validation intent (carries source_finding_id; a worker reproduces it from scratch or withdraws it). Do NOT create your own validation intent for a finding — those appear by themselves. Only dispatch follow-ups for coverage-ledger needs_follow_up rows and for chaining.
   - **One vuln × one component per intent**: never a broad "test the app" or "test authorization" intent. Split by vulnerability class AND by component — one intent per (vuln_class × endpoint-group / exported-component / storage-area), and for authz/IDOR one per role pair. Four narrow intents beat one wide one; the worker pool runs them in parallel.

5. **Submit**: Call add_intent ONCE in batch with new directions (up to 4 highest-value intents):
   - **summary**: One-sentence natural language description (full target address + what to do + why).
   - **asset_ids**: Target asset IDs from list_assets.
   - **parent_ids**: Upstream node IDs if synthesized from prior facts.
   - **vuln_class + component + skills**: ONE vulnerability class on ONE component per intent, with 1-3 worker skills. Prefer several narrow intents (idor on accounts API, idor on beneficiaries API) over one broad "test authorization" intent.

6. **Finishing**: proving the last open goal completes the task, so the system refuses it while intents are open/running, while needs_follow_up coverage rows remain, or (with 2+ confirmed findings) without chain_analysis. Before the last prove_goal: wait for or kill_work remaining work, reconcile the ledger, and genuinely try to chain confirmed findings into higher-impact paths (dispatch intents to test plausible chains).

Be concise, focused, and efficient.`

func plannerSystem(goal, dataDir, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir)
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// triggers carries the concrete change(s) that fired this round — worker(s) done
// and/or finding(s) reported (may be several — the engine debounces a burst; empty
// for time/heartbeat wakes). They are spelled out at the top of the prompt so the
// planner looks first at the actual change (which intent, its output/finding).
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, triggers []TriggerEvent, emit func(db.Activity)) (met bool, reason string, err error) {
	// cold-digest §2.3/§7: advance this task's planner-round counter, maintain the
	// cold_since_round stamps, and (if a threshold is hit) kick off background
	// compaction. Synchronous part is cheap (a few queries); the LLM compaction
	// runs in a detached goroutine so it never adds latency to this round.
	p.compactor.OnPlannerRound(ctx, ts)
	tsx := NewToolSet(ts, "planner")
	tsx.SetFindingRecorder(p.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.killWork = p.killWork   // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork // enable steer_work tool (nil = unavailable)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// Domain tools plus base tools: Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash.
	// Remove add_task_scope/list_untested_assets from the prompt when asset coverage is disabled.
	base := append(tsx.DropCoverageTools(tsx.PlannerTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// Put completed intents and the prefetched graph in this round's user input below; the system
	// contains only the static planning body for stable caching. Long rounds could compact that state,
	// but planning rounds are usually short. situational is appended to input below.
	situational := renderTriggers(ts, triggers) + renderGraphOverview(tsx.graphOverviewData()) + threatModelBlock(ts, "planner") + coverageBlock(ts)
	// Task deadline/final mode arrives via ctx (taskclock.go). Append final-round timeout instructions
	// to this user input with situational, restricting the planner to final goal assessment
	// without new intents.
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n[Final task cleanup (special instructions for this round override normal planning above)]:" + resolveTaskTimeoutWrapup("planner")
	}
	// Create the task workspace <workDir>/tasks/<taskID> first.
	taskDir := ensureRunDir(p.workDir, taskID, 0)
	ctx = intercept.WithReviewContext(ctx, taskDir, intercept.ReviewBackground{})
	sysBody := plannerSystem(goal, p.workDir, taskDir)
	if p.wantConstraints() {
		sysBody += constraintBlock(ts) // Inject operational constraints into the system prompt to bound exploration.
	}
	system, boundary := deferredSystem(sysBody, def)
	// Planner has no own wall-clock budget; clamp MaxDuration to remaining task deadline so
	// expiry settles correctly (task-timeout prompt for time, per-run prompt for step limit).
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // Record through the proxy; trust its CA for MITM-signed HTTPS certificates.
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// Optional web search: ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is a separate http/https/socks5 egress proxy, not the recording MITM proxy; empty means direct.
		EnableWebSearch:       p.webSearch.Enabled,
		WebSearchBackend:      p.webSearch.Backend,
		BraveSearchAPIKey:     p.webSearch.BraveKey,
		TavilySearchAPIKey:    p.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: p.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  p.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   p.webSearch.DeepSeekModel,
		WebSearchProxy:        p.webSearch.Proxy,
		BashEnv:               proxyEnv(p.proxyAddr, p.proxyCACert), // Bash subprocesses use the proxy and trust its CA by default.
		WorkingDir:            taskDir,                              // Task workspace: <workDir>/tasks/<taskID>.
		ToolOutputDir:         cmdOutDir(taskDir),
		MaxTurns:              p.maxTurns, // 0 = unlimited (configurable in agent management)
		MaxDuration:           maxDur,     // 0 means unlimited; with a deadline, use remaining time.
		Compaction:            compactionConfig(p.compactionWindow()),
		// Share planning todos across wakeups to preserve serial chains; sessions refresh but the store persists.
		Todos: p.todoFor(ts.ID()),
		// At this round's step limit, persist decisions through add_intent/prove_goal and serial chains
		// through TodoWrite. Planning continues on later wakeups, rather than ending the task.
		// When clamped by task deadline, use PromptByReason (wrapupSettlementForTask).
		Settlement:   settle,
		NonStreaming: p.nonStreaming(), // Non-streaming profiles use Provider.Complete.
		MaxTokens:    p.maxTokens(),    // 0 omits the output limit, leaving the server default.
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// Experimental noa compaction persists archives under <workDir>/noa/<SessionID>.
	noaSession := fmt.Sprintf("exp%d-planner", ts.ID())
	enableNoa(&opts, p.noaEnabledFn, p.workDir, noaSession, noaWarn(noaSession))
	// Put completed intents and full graph in user input, alongside instructions and shared todos.
	// The todo is the model's regenerable planning scratchpad, so user input is sufficient.
	// Opening depends on concrete changes: point to the changes block when present; otherwise
	// (heartbeat/hint/resume) review running intents without claiming the graph changed.
	lead := "A concrete change just occurred (see [Actual changes triggering this round] below); plan the next step accordingly:"
	if len(triggers) == 0 {
		lead = "This is a **periodic heartbeat / wakeup without a concrete change signal**; the graph may be unchanged. Review running intents: use steer_work for stalled/drifting work and kill_work for entirely wrong directions. Then assess goals and whether to add directions:"
		// With no open/running intents on a heartbeat, no Worker or queued direction remains.
		// Tell the planner explicitly to produce a new direction instead of spending an idle round.
		if active, err := ts.HasActiveIntent(); err == nil && !active {
			lead = "This is a **periodic heartbeat** with **no open or running intents**: no active Worker or queued direction remains, so exploration has stopped. You **must** produce one or more new, nonduplicate intents advancing the goal (zero intents is not allowed). First assess whether goals are achieved; if not, add directions immediately:"
		}
	}
	input := lead + situational + "\n\nAssess goals from this state. Use prove_goal for each goal actually achieved (the required result obtained or target vulnerability confirmed). **Hard rule: if goals are unmet and no intent is open or running (frontier_open=0 and running_intents is empty), produce at least one intent advancing the goal in this round. There is no active work or queue to wait for; zero intents would stall the task. Only when existing open/running intents are progressing or goals are achieved may this round produce no new intents.**" +
		renderPlannerTodos(opts.Todos.List())
	// MaxDuration now interrupts tools and settles in a live context, so stuck rounds cannot
	// bypass settlement. No external hard timeout is needed; ctx handles pause/kill/shutdown.
	_, _, err = captureRun(ctx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
