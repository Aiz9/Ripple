package agent

import (
	"context"
	"errors"
	"fmt"
)

// AbortCause names why an agent run's context was cancelled. Every cancellation
// site should attach one so the activity trace can report the real initiator.
type AbortCause struct {
	Code  string
	Short string
	Text  string
}

func (c *AbortCause) Error() string { return c.Text }

func cause(code, short, text string) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: text}
}

// Causef builds a cause that includes runtime-specific detail.
func Causef(code, short, format string, args ...any) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: fmt.Sprintf(format, args...)}
}

var (
	// Task-level execution context.
	AbortPausedByUser = cause("paused_by_user", "User paused the task",
		"The user paused the task through POST /api/tasks/{id}/control with action=pause. This Planner/Worker run was cancelled; running intents return to frontier(open) and are reclaimed and restarted when the task resumes.")
	AbortPausedByOrchestrator = cause("paused_by_orchestrator", "Orchestration agent paused the task",
		"The orchestration agent called pause_task. This Planner/Worker run was cancelled; running intents return to frontier(open) and restart when the task resumes.")
	AbortTaskDeleted = cause("task_deleted", "Task deleted",
		"The task is being deleted (DELETE /api/tasks/{id}). The deletion barrier cancelled its Planner, Workers, and main agent; results of this run will no longer be used.")
	AbortPausedOnReload = cause("paused_on_reload", "Backend restored the task's paused state",
		"The backend restored the persisted paused state at startup and cancelled this run. Normally no agents are running during restoration.")
	AbortGoalMet = cause("goal_met", "Planner marked goals met",
		"The planner marked the task done after determining its goals were achieved, then cancelled remaining Workers. Those intents are marked stopped rather than failed.")
	AbortSettleDrainTimeout = cause("settle_drain_timeout", "Task cleanup grace expired",
		"After task timeout the engine waited for Workers to finish gracefully, but the 90-second drain grace period expired. Hard cancellation marks intents exhausted and preserves facts and assets already saved during cleanup.")

	// Per-work context.
	AbortKilledByPlanner = cause("killed_by_planner", "Planner terminated this intent",
		"The planner called kill_work, usually because the direction drifted or no longer had value. The intent is marked stopped and will not be reclaimed automatically.")
	AbortWorkPausedByUser = cause("work_paused_by_user", "User paused this Worker intent",
		"The user paused the running Worker. The call was cancelled and the intent became paused. All registered intents, facts, findings, and activities are preserved; resuming restarts execution from the beginning.")
	AbortWorkCancelledByUser = cause("work_cancelled_by_user", "User deleted this Worker intent",
		"The user deleted the running Worker. The call was cancelled. After the Worker leaves the write section, the server applies the selected deletion mode: soft deletion preserves outputs; hard deletion cascades to this intent and descendants supported only by it.")
	AbortWorkFinished = cause("work_finished", "Worker finished normally",
		"The Worker completed normally and detachWork released its context. This is not an interruption; seeing this in an interruption message indicates a cancellation/cleanup race.")
	AbortPausedRaceGuard = cause("paused_race_guard", "Run rejected while paused",
		"The engine refused a new execution context while paused to prevent a claim/pause race from starting another Worker. Claimed intents return to the frontier.")

	// Main Agent and standalone conversation contexts.
	AbortChatStoppedByUser = cause("chat_stopped_by_user", "User stopped this conversation turn",
		"The user clicked stop and cancelled this main-agent or session-agent run. Existing activity records are preserved, and another message can continue the session.")
	AbortChatPausedWithTask = cause("chat_paused_with_task", "Main chat paused with task",
		"Pausing the task also cancelled its running main-agent conversation. Existing activity is preserved; resuming does not automatically replay this turn's message.")
	AbortChatTurnFinished = cause("chat_turn_finished", "Conversation turn finished",
		"The turn completed normally and the server is releasing its context. This is not an interruption; seeing this in an interruption message indicates a cancellation/cleanup race.")

	// Process-level and per-run hard backstop.
	AbortShutdown = cause("shutdown", "Backend process is shutting down",
		"The backend received SIGINT or SIGTERM and is restarting, updating, or shutting down. All running agents are cancelled. After restart, remaining running intents are reset to open and executed again.")
	AbortRunHardTimeout = cause("run_hard_timeout", "Per-run hard timeout backstop triggered",
		"The run exceeded its soft wall-clock budget and grace period. A model request or tool likely did not return, so normal turn cleanup could not run. Check the last unfinished tool call before interruption")
)

// AbortReason resolves the named cause attached to a cancelled run context.
func AbortReason(ctx context.Context) (code, short, text string, ok bool) {
	c := context.Cause(ctx)
	if c == nil {
		return "", "", "", false
	}
	var ac *AbortCause
	if errors.As(c, &ac) {
		return ac.Code, ac.Short, ac.Text, true
	}
	switch {
	case errors.Is(c, context.DeadlineExceeded):
		return "deadline_exceeded", "Upstream context deadline reached",
			"The upstream context reached its deadline without a named WithTimeoutCause reason: " + c.Error(), true
	case errors.Is(c, context.Canceled):
		return "canceled_no_cause", "Cancellation has no named cause",
			"The upstream context was cancelled without a named context.WithCancelCause reason. Register the reason in agent/cancelcause.go and wire it to the cancellation point.", true
	default:
		return "other", firstLine(c.Error(), 80), c.Error(), true
	}
}
