package server

import (
	"strings"
	"testing"
)

// A long task goal repeated per event was the dominant bloat. These tests pin the
// fix: the task-context header (description + goal) is rendered ONCE per task, no
// matter how many same-task fires are merged.

const longGoal = "\u62ff\u5230\u9898\u76ee f2-05 \u7684\u53d7\u4fdd\u62a4 flag \u5e76\u901a\u8fc7 submit_flag \u63d0\u4ea4\uff1b\u672c\u9898\u5bc6\u6587\u5df2\u9ad8\u5ea6\u6536\u655b\uff0cflag \u53ea\u80fd\u7531\u4e8c\u8fdb\u5236\u5185\u5d4c\u6570\u636e\u6d3e\u751f\u2026\u2026" // Represents several thousand characters of inherited facts.

func sameTaskFires(n int) []triggeredRun {
	items := make([]triggeredRun, n)
	for i := range items {
		items[i] = triggeredRun{
			agentKey: "tec_benchmark", taskID: 72, taskDesc: "f2-05 \u9006\u5411", taskGoal: longGoal,
			message: "\u3010\u672c\u6b21\u7531\u5de5\u5177\u8c03\u7528\u89e6\u53d1\u3011\n\u5de5\u5177: submit_flag\n\u5165\u53c2: {...}\n\u8fd4\u56de: {correct:false}", mergeable: true,
		}
	}
	return items
}

func TestMergeAllRunsWritesTaskGoalOnce(t *testing.T) {
	out := mergeAllRuns(sameTaskFires(39))
	if got := strings.Count(out.message, longGoal); got != 1 {
		t.Fatalf("same-task goal should appear exactly once in a merged-all run, got %d", got)
	}
	if strings.Count(out.message, "── Trigger ") < 1 || !strings.Contains(out.message, "Trigger 39") {
		t.Fatalf("all 39 event bodies should be present: %q", out.message)
	}
	// A merged run embeds its header inline, so finalTriggerMessage must not re-add it.
	if out.taskDesc != "" || out.taskGoal != "" {
		t.Fatalf("merged run must clear taskDesc/taskGoal to avoid a duplicate header")
	}
	if finalTriggerMessage(out) != out.message {
		t.Fatalf("finalTriggerMessage must not prepend another header for a merged run")
	}
}

func TestMergeAllRunsGroupsInterleavedTasks(t *testing.T) {
	// Fires from two tasks arriving interleaved (A,B,A,B) must still carry each
	// task's context exactly once — grouping, not per-event repetition.
	mk := func(id int64, goal string) triggeredRun {
		return triggeredRun{agentKey: "a", taskID: id, taskDesc: "d", taskGoal: goal, message: "body", mergeable: true}
	}
	out := mergeAllRuns([]triggeredRun{mk(1, "GOAL_A"), mk(2, "GOAL_B"), mk(1, "GOAL_A"), mk(2, "GOAL_B")})
	if got := strings.Count(out.message, "GOAL_A"); got != 1 {
		t.Fatalf("task #1 goal should appear once despite interleaving, got %d", got)
	}
	if got := strings.Count(out.message, "GOAL_B"); got != 1 {
		t.Fatalf("task #2 goal should appear once despite interleaving, got %d", got)
	}
	if !strings.Contains(out.message, "across 2 tasks") {
		t.Fatalf("header should report 2 tasks: %q", out.message)
	}
	if got := strings.Count(out.message, "── Trigger "); got != 4 {
		t.Fatalf("all 4 event bodies should be present, got %d", got)
	}
}

func TestMergeTriggeredRunsWritesTaskGoalOnce(t *testing.T) {
	out := mergeTriggeredRuns(sameTaskFires(5))
	if got := strings.Count(out.message, longGoal); got != 1 {
		t.Fatalf("same-task goal should appear exactly once in a by-task merge, got %d", got)
	}
}

func TestFinalTriggerMessageSingleFirePrependsHeaderOnce(t *testing.T) {
	item := sameTaskFires(1)[0]
	msg := finalTriggerMessage(item)
	if got := strings.Count(msg, longGoal); got != 1 {
		t.Fatalf("single fire should carry the task goal exactly once, got %d", got)
	}
	if !strings.HasPrefix(msg, "[Task #72") {
		t.Fatalf("single fire should be prefixed with the task-context header: %q", msg)
	}
}

func TestTaskContextHeaderEmptyForIntervalFire(t *testing.T) {
	if h := taskContextHeader(0, "", ""); h != "" {
		t.Fatalf("interval/none trigger (no task) must produce no header, got %q", h)
	}
	// An interval fire's message must pass through untouched.
	item := triggeredRun{message: "\u5b9a\u65f6\u89e6\u53d1\u6b63\u6587"}
	if finalTriggerMessage(item) != "\u5b9a\u65f6\u89e6\u53d1\u6b63\u6587" {
		t.Fatalf("interval fire message must pass through unchanged")
	}
}

func TestTaskContextHeaderTruncatesLongGoal(t *testing.T) {
	huge := strings.Repeat("\u5f88", 5000)
	h := taskContextHeader(72, "d", huge)
	if len([]rune(h)) > 800 { // 200 description + 500 goals + truncation/decorations, far below 5000.
		t.Fatalf("header should be bounded even for a huge goal, got %d runes", len([]rune(h)))
	}
}
