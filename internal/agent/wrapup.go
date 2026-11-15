package agent

import (
	"strings"

	"github.com/Autumn-27/norma/harness"
)

// At MaxTurns or run_seconds/MaxDuration exhaustion, SDK settlement injects this prompt
// to persist identified unsaved results and output a summary, avoiding unfinished runs.
// Both turn-limit and timeout exits follow the settlement path.
//
// Each agent may override its body in agents.wrapup_prompt; empty uses built-in defaults.
// Tool exclusions and settlement budgets are code-owned policies; only prompt text is editable.

// WrapupOverride, if set, returns the stored wrap-up prompt for an agent key and
// whether a non-empty one exists. Wired by the server to the agents table (like
// PromptOverride for system prompts). nil / empty → the built-in default is used.
var WrapupOverride func(agentKey string) (string, bool)

// WrapupMaxTurnsOverride, if set, returns the admin-configured turn budget for the
// wrap-up phase of an agent and whether a positive one exists. Wired to the agents
// table. nil / ≤0 → the built-in per-agent default (wrapupTurnDefaults) is used.
var WrapupMaxTurnsOverride func(agentKey string) (int, bool)

// Built-in prompts indexed by agent key; worker reuses settleWrapUpPrompt from worker.go,
// planner/mainagent have their own, and unknown/custom agents use the generic fallback.
var wrapupDefaults = map[string]string{
	"worker":    settleWrapUpPrompt,
	"planner":   plannerWrapUpDefault,
	"mainagent": mainAgentWrapUpDefault,
}

// wrapupTurnDefaults sets settlement's own turn budget, overridable by positive DB values.
// All defaults allow 10 turns to persist outputs; unknown agents use genericWrapupTurns.
var wrapupTurnDefaults = map[string]int{
	"worker":    10,
	"planner":   10,
	"mainagent": 10,
}

const genericWrapupTurns = 10

const plannerWrapUpDefault = "This planning round is nearly out of steps. Only this round is ending; the system will wake you again as state changes. Do not close the whole task or invent intents merely for cleanup (zero intents can be normal). Persist decisions already reached: (1) batch currently justified directions through add_intent; (2) mark goals proven by facts/findings using prove_goal; (3) record multistep serial exploit chains in TodoWrite for later wakeups. Then end the round without a summary."

const mainAgentWrapUpDefault = "This interaction is nearly out of steps. Do not initiate further exploration/actions. Output one standalone plain-text sentence summarizing progress, key conclusions, and the recommended next step."

const genericWrapUpDefault = "Your budget is about to expire. Persist completed unsaved results, then output one standalone plain-text sentence summarizing actions and key conclusions; it will be displayed as the run result."

// WrapupDefault returns the built-in default wrap-up prompt for an agent key —
// used by the admin UI as the "restore default" value and empty-field placeholder.
func WrapupDefault(agentKey string) string {
	if d, ok := wrapupDefaults[agentKey]; ok {
		return d
	}
	return genericWrapUpDefault
}

// WrapupTurnsDefault returns the built-in wrap-up turn budget for an agent key —
// used by the admin UI as the "0 = default N" hint.
func WrapupTurnsDefault(agentKey string) int {
	if n, ok := wrapupTurnDefaults[agentKey]; ok {
		return n
	}
	return genericWrapupTurns
}

// resolveWrapup returns the effective wrap-up prompt: the DB override (if set and
// non-empty) over the built-in default.
func resolveWrapup(agentKey string) string {
	if WrapupOverride != nil {
		if t, ok := WrapupOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return WrapupDefault(agentKey)
}

// resolveWrapupTurns returns the effective wrap-up turn budget: a positive DB
// override over the built-in per-agent default.
func resolveWrapupTurns(agentKey string) int {
	if WrapupMaxTurnsOverride != nil {
		if v, ok := WrapupMaxTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return WrapupTurnsDefault(agentKey)
}

// wrapupSettlement builds the settlement config for an agent's run. Prompt and the
// turn budget are admin-editable per agent; disabled tools are code-owned policy so
// a user can't edit away the "stop probing" guardrail. Resolved fresh each run
// (reads DB live), so edits apply on the next run without a restart.
func wrapupSettlement(agentKey string, disabledTools []string) *harness.Settlement {
	return &harness.Settlement{
		Prompt:        resolveWrapup(agentKey),
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
}

// Task-timeout settlement prompts.
//
// Per-run exhaustion differs from whole-task expiry. Their meanings can be opposite:
// planners continue planning after per-run exhaustion but stop and assess final goals at task expiry.
// Only Worker/planner have task-timeout prompts.

// Task-timeout body/turn overrides are wired to agents.task_timeout_wrapup_prompt and
// task_timeout_wrapup_max_turns for Worker/planner only.
var (
	WrapupTaskTimeoutOverride      func(agentKey string) (string, bool)
	WrapupTaskTimeoutTurnsOverride func(agentKey string) (int, bool)
)

var taskTimeoutWrapupDefaults = map[string]string{
	"worker":  workerTaskTimeoutDefault,
	"planner": plannerTaskTimeoutDefault,
}

const workerTaskTimeoutDefault = "The entire task has reached its timeout and is ending (not just this run's budget). Final opportunity: (1) save ALL identified unsaved results with insert_assets / record_fact / report_finding; (2) do not start new commands/probes; (3) finish with one standalone plain-text sentence summarizing this intent's key conclusions."

const plannerTaskTimeoutDefault = "The entire task has reached its timeout and is ending, not just this round. Make one final goal assessment from ALL current facts/findings. Call prove_goal for every evidence-proven goal. Do not generate new intents because they will not execute. Finish without a summary."

// TaskTimeoutWrapupDefault supplies built-in task-timeout text for UI placeholders/reset.
func TaskTimeoutWrapupDefault(agentKey string) string {
	return taskTimeoutWrapupDefaults[agentKey] // Mainagent/chat have no such prompt and return empty.
}

// resolveTaskTimeoutWrapup prefers nonempty DB text, then built-in text. Empty means the agent
// has no task-timeout prompt and the caller should fall back to per-run wording.
func resolveTaskTimeoutWrapup(agentKey string) string {
	if WrapupTaskTimeoutOverride != nil {
		if t, ok := WrapupTaskTimeoutOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return TaskTimeoutWrapupDefault(agentKey)
}

func resolveTaskTimeoutTurns(agentKey string) int {
	if WrapupTaskTimeoutTurnsOverride != nil {
		if v, ok := WrapupTaskTimeoutTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return resolveWrapupTurns(agentKey) // Default to per-run settlement turns.
}

// wrapupSettlementForTask builds settlement for a worker/planner run that is aware
// of the task deadline. See §5 of the design doc:
//   - clamped=true: time expiry means task deadline, so use task-timeout wording;
//     MaxTurns means steps ended first while task time remains, so use per-run wording.
//   - clamped=false: task deadline is distant; both reasons use per-run wording.
//
// Harness PromptByReason selects the actual reason at settlement time, avoiding build-time mismatch.
func wrapupSettlementForTask(agentKey string, disabledTools []string, clamped bool) *harness.Settlement {
	perRun := resolveWrapup(agentKey)
	st := &harness.Settlement{
		Prompt:        perRun, // Fallback, also used for both reasons when unclamped.
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
	if clamped {
		if tt := resolveTaskTimeoutWrapup(agentKey); tt != "" {
			st.PromptByReason = map[harness.TerminalReason]string{
				harness.ReasonTimeout:  tt,     // Task deadline reached.
				harness.ReasonMaxTurns: perRun, // Step limit reached while task time remains.
			}
			st.MaxTurns = resolveTaskTimeoutTurns(agentKey)
		}
	}
	return st
}
