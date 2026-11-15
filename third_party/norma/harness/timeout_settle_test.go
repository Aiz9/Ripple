package harness

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
)

// drainWithCtx is drain() over a caller-supplied ctx, so a test can cancel the
// parent (pause/kill/shutdown) independently of the run's own MaxDuration budget.
func drainWithCtx(t *testing.T, ctx context.Context, in QueryInput, deps QueryDeps) *Terminal {
	t.Helper()
	var term *Terminal
	for ev, err := range Query(ctx, in, deps) {
		if err != nil {
			t.Fatalf("event err: %v", err)
		}
		if ev.Kind == KindResult {
			term = ev.Terminal
		}
	}
	if term == nil {
		t.Fatal("no terminal event")
	}
	return term
}

// When a tool overruns the MaxDuration wall-clock budget, the tool is interrupted
// at the deadline and the run enters the WRAP-UP phase (settlement) on the live
// ctx — finishing with ReasonTimeout and the wrap-up prompt injected — instead of
// dying with ReasonAbortedTools. This is the hung/slow-tool case that the old
// turn-boundary-only budget check could never settle.
func TestSettlementOnToolOverrunsBudget(t *testing.T) {
	m := &scriptedModel{turns: [][]llm.StreamEvent{
		toolTurn("s1", "sleep", `{"seconds":3600}`),                  // hangs far past MaxDuration
		textTurn("\u5df2\u5199\u56de\u4e8b\u5b9e\u5e76\u603b\u7ed3"), // settlement turn → natural stop
	}}
	in := QueryInput{
		Messages:       []llm.Message{llm.UserText("go")},
		Tools:          tool.NewRegistry(tool.NewSleep()),
		PermissionMode: permission.ModeBypass,
		WorkingDir:     t.TempDir(),
		MaxDuration:    100 * time.Millisecond, // budget the run so the sleep overruns it
		Settlement:     &Settlement{Prompt: "SETTLE_ON_TIMEOUT \u8bf7\u5199\u56de\u4e8b\u5b9e"},
	}
	term := drainWithCtx(t, context.Background(), in, QueryDeps{CallModel: m.call})

	if term.Reason != ReasonTimeout {
		t.Fatalf("reason=%v, want ReasonTimeout\uff08\u5de5\u5177\u8d85\u5899\u2192\u5c31\u5730\u6536\u5c3e\uff0c\u975e aborted_tools\uff09", term.Reason)
	}
	found := false
	for _, msg := range term.Messages {
		for _, c := range msg.Content {
			if strings.Contains(c.Text, "SETTLE_ON_TIMEOUT") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("\u8d85\u5899\u6536\u5c3e\u63d0\u793a\u672a\u88ab\u6ce8\u5165\u5230\u5bf9\u8bdd")
	}
	if m.calls != 2 {
		t.Fatalf("\u5e94\u6709 2 \u6b21\u6a21\u578b\u8c03\u7528(\u4e3b+\u6536\u5c3e)\uff0c\u5f97 %d", m.calls)
	}
}

// Regression guard: a PARENT-ctx cancellation (pause / planner kill / shutdown) —
// as opposed to the run's own budget — still aborts with ReasonAbortedTools and
// does NOT enter the wrap-up phase.
func TestParentCancelStillAbortsNoSettlement(t *testing.T) {
	m := &scriptedModel{turns: [][]llm.StreamEvent{
		toolTurn("s1", "sleep", `{"seconds":3600}`),
		textTurn("would-be settlement"), // must NOT be reached
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	in := QueryInput{
		Messages:       []llm.Message{llm.UserText("go")},
		Tools:          tool.NewRegistry(tool.NewSleep()),
		PermissionMode: permission.ModeBypass,
		WorkingDir:     t.TempDir(),
		// no MaxDuration: the only deadline is the parent ctx above
		Settlement: &Settlement{Prompt: "SHOULD_NOT_APPEAR"},
	}
	term := drainWithCtx(t, ctx, in, QueryDeps{CallModel: m.call})

	if term.Reason != ReasonAbortedTools {
		t.Fatalf("reason=%v, want ReasonAbortedTools\uff08\u7236 ctx \u53d6\u6d88=\u771f\u4e2d\u65ad\uff0c\u4e0d\u6536\u5c3e\uff09", term.Reason)
	}
	for _, msg := range term.Messages {
		for _, c := range msg.Content {
			if strings.Contains(c.Text, "SHOULD_NOT_APPEAR") {
				t.Fatalf("\u7236 ctx \u53d6\u6d88\u65f6\u4e0d\u5e94\u8fdb\u5165\u6536\u5c3e\uff0c\u5374\u6ce8\u5165\u4e86\u6536\u5c3e\u63d0\u793a")
			}
		}
	}
	if m.calls != 1 {
		t.Fatalf("\u7236\u53d6\u6d88\u540e\u4e0d\u5e94\u518d\u8c03\u7528\u6a21\u578b\u6536\u5c3e\uff0c\u6a21\u578b\u8c03\u7528\u6570=%d\uff0cwant 1", m.calls)
	}
}
