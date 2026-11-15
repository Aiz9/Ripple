package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/internal/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// goalsDefaultTmpl is the built-in editable body (section [A]) for the goals decomposer
// prompt, seeded into agent_prompts. No template vars are used today.
const goalsDefaultTmpl = `You are the penetration testing constraint extractor. Your ONLY job is to read the operator's task goal and description and register any **explicit** operational constraints they state. You do NOT decompose, split, rephrase, score, or invent goals — the system stores the operator's goal text verbatim as the goal.

**Extract operational constraints (only when explicitly stated):**
Identify clear rules the operator states about what operations are allowed or prohibited, and register each with set_constraints:
- type=deny: an explicit prohibition (e.g., "do not port scan", "no write/delete operations in production", "no brute force", "do not touch subdomain X").
- type=allow: an explicit scope restriction (e.g., "passive reconnaissance only", "test only domain X").
- A constraint is an operator RULE, not background. Descriptive context — the kind of app, the assessment methodology, the report format, the standard being followed, the target's identifiers — is NOT a constraint. Register a constraint ONLY for an explicit allow/deny directive.
- **Constraints must be self-contained with explicit targets**: Replace pronouns like "current target / current port / current IP / this host" with the actual value from the goal/description. Constraints are injected into execution prompts where pronouns lose their context.
  Example: Target is https://abc.example.net → write "Only test abc.example.net" rather than "Only test current target"; "Only test port 443, do not scan other ports" rather than "Only test current port".
- **Only register constraints the operator explicitly states; never infer or invent them.** If it is unclear whether a sentence is a rule or merely background, do NOT create a constraint.
- If no explicit operational constraint is stated, **do not** call set_constraints at all.

Do not call set_goals — goals are stored verbatim by the system, not decomposed here.`

// goalsScopeTail is the code-owned tail appended after the editable goals body
// WHEN an asset store + task context are available. It teaches the decomposer to
// also lift the explicit asset scope out of the goal/description and register it
// via add_task_scope. Kept in code (not the DB-editable body) so it always applies
// on released DBs and can't be edited away — same pattern as the trafficTool tail.
const goalsScopeTail = `

**Additional Responsibility: Register In-Scope Target Assets**
In addition to extracting constraints, identify the **explicit testing asset scope** specified in the task goal/description, and call add_task_scope to register it (defines the task authorization boundary and coverage denominator). **Principle of Least Scope: Only register targets explicitly designated by the user; never broaden without authorization.**
- If target is a URL or address with hostname (e.g. https://xxx.example.com/path, app.example.com) → extract its **full hostname**, kind=subdomain, value=full hostname.
  Example: Target https://a1b2c3.lab.example.net/path → kind=subdomain, value=a1b2c3.lab.example.net (**NOT** example.net).
  **Never truncate a hostname with subdomains into a root domain**—registering example.com when seeing xxx.example.com broadens scope beyond authorization.
- Pure IP or network range → kind=ip / cidr, value=IP or CIDR.
- **Do not** register company scope—at task inception, company entities typically do not exist yet; company-level scope is handled in subsequent planning stages.
Other rules:
- Only register scope **explicitly stated in the goal/description**; never fabricate or deduce unmentioned domains/IPs.
- reason: brief note citing the sentence providing justification for auditability.
- If no explicit target asset scope is mentioned, **do not** call add_task_scope.
Use add_task_scope to register scope (if any). Do not call set_goals.`

// GoalSpec is one decomposed objective.
type GoalSpec struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

// DecomposeGoals runs the round-0 LLM pass that extracts explicit operational
// constraints (set_constraints) and, when an asset store is wired, the explicit
// asset scope (add_task_scope) from the task goal/description. It does NOT
// decompose goals: the operator's goal text is stored verbatim by createGoals,
// so this pass never writes goal nodes and always returns nil. The name is kept
// for the stable call sites.
//
// prov is supplied by the caller (rather than built here from a Config) so this
// pass rides the SAME provider instance as the rest of the engine — it
// shares the rate limiter, gets recorded by llmrec, and participates in LLM
// failover instead of quietly bypassing all three.
//
// desc is free-text task background: target scope, flag count, engagement instructions, etc.
// It is fed alongside the goal so constraint/scope extraction has context — the
// prompt forbids inventing anything the two texts don't explicitly state.
//
// emit, when non-nil, receives every LLM step (thinking/tool_use/result) with
// Worker="planner" so the round-0 activity is visible in the UI.
//
// as + taskID, when non-nil/positive, wire the add_task_scope tool so the pass
// can register the explicit asset scope it extracts from the goal.
//
// ts is the task's exploration store, used for set_constraints/add_task_scope
// provenance. It returns nil (goals are written verbatim elsewhere).
func DecomposeGoals(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	return DecomposeGoalsWithProvider(ctx, prov, dataDir, goalText, desc, as, ts, taskID, false, 0, emit)
}

// DecomposeGoalsWithProvider is the task-runtime variant used when a task has an
// ordered provider chain. It preserves the same tools and write behavior while
// letting the caller own provider selection/failover. maxTokens is the profile's
// per-reply output cap (0 = send none).
func DecomposeGoalsWithProvider(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, nonStreaming bool, maxTokens int, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	// Goal decomposition is one-shot without a transcript store, so agentcore does not attach
	// a session ID to ctx (it does so only with a writer; see agentcore.Prompt). Gateways
	// using session headers for caching/sticky routing (opencode zen requires x-opencode-session)
	// otherwise return 400 MissingSessionID here even while conversations work.
	// Attach a stable exploration-specific ID for caching, distinct from planner/worker IDs,
	// so llmrec.parseSession can attribute usage correctly.
	if ts != nil {
		ctx = transcript.WithSessionID(ctx, fmt.Sprintf("exp%d-goals", ts.ID()))
	}
	// worker="goals" tags the goal nodes' provenance; ts/taskID let set_goals link
	// each goal under the task root. This is the catalog's real set_goals tool, so a
	// web-edited description/schema on it applies here too.
	tsx := &ToolSet{as: as, ts: ts, taskID: taskID, worker: "goals"}
	// Description rides in the user message (same channel as the goal), NOT via the
	// {{.EngagementDescription}} template var — else a prompt that references the var
	// would inject the description twice. System prompt stays pure static instructions.
	sys := renderSystem("goals", goalsDefaultTmpl, GoalsVars{DataDir: dataDir, Now: nowStr()})
	// Goals are stored verbatim by createGoals, so this round-0 pass does NOT get
	// set_goals — it only extracts operational constraints (and scope, below). This is
	// what keeps the operator's goal text from being reshaped/split by the LLM.
	tools := []actool.CoreTool{tsx.setConstraints()}
	// Wire add_task_scope only when we have a real asset store + task to write to.
	// The scope-extraction tail is appended in lockstep so the prompt never asks for
	// a tool that isn't present.
	if as != nil && taskID > 0 {
		tools = append(tools, tsx.addTaskScope())
		sys += goalsScopeTail
	}
	sys += outputLanguage
	userMsg := "Task goals:\n" + goalText
	if d := strings.TrimSpace(desc); d != "" {
		userMsg += "\n\nTask description (background may include target scope, flag count, or engagement instructions; use only as reference and do not invent missing details):\n" + d
	}
	// Use captureRun so every LLM step is emitted as an activity record (visible in
	// the plan tab under the round-0 marker). Falls back gracefully when emit is nil.
	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	}
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  tools,
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,
		// Allow enough turns for constraint extraction and scope registration calls.
		MaxTurns:     8,
		NonStreaming: nonStreaming, // Non-streaming profiles use Provider.Complete.
		MaxTokens:    maxTokens,    // 0 omits the output limit, leaving the server default.
	}, userMsg, captureEmit)
	// This pass only writes constraints/scope (side effects above); it never writes
	// goal nodes, so there is nothing to read back. createGoals stores the goal verbatim.
	return nil
}
