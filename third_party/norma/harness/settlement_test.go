package harness

import (
	"context"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
)

// On hitting MaxTurns with a Settlement configured, the loop injects the wrap-up
// prompt, hides DisabledTools during wrap-up, and finishes with the ORIGINAL
// budget reason (not ReasonCompleted).
func TestSettlementOnBudgetHit(t *testing.T) {
	var toolsSeen [][]string
	turns := [][]llm.StreamEvent{
		toolTurn("a", "Bash", `{"command":"echo 1"}`),                // turn 1 → hits MaxTurns=1
		textTurn("\u5df2\u5199\u56de\u4e8b\u5b9e\u5e76\u603b\u7ed3"), // settlement turn → natural stop
	}
	call := func(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
		names := make([]string, 0, len(req.Tools))
		for _, ts := range req.Tools {
			names = append(names, ts.Name)
		}
		i := len(toolsSeen)
		toolsSeen = append(toolsSeen, names)
		evs := turns[i]
		return func(yield func(llm.StreamEvent, error) bool) {
			for _, ev := range evs {
				if !yield(ev, nil) {
					return
				}
			}
		}
	}
	in := QueryInput{
		Messages:       []llm.Message{llm.UserText("go")},
		Tools:          tool.NewRegistry(tool.NewBash()),
		PermissionMode: permission.ModeBypass,
		WorkingDir:     t.TempDir(),
		MaxTurns:       1,
		Settlement:     &Settlement{Prompt: "SETTLE_NOW \u8bf7\u5199\u56de\u4e8b\u5b9e", DisabledTools: []string{"Bash"}},
	}
	term := drain(t, in, QueryDeps{CallModel: call})

	if term.Reason != ReasonMaxTurns {
		t.Fatalf("reason=%v, want ReasonMaxTurns\uff08\u6536\u5c3e\u540e\u4ecd\u62a5\u539f\u9884\u7b97 reason\uff09", term.Reason)
	}
	found := false
	for _, m := range term.Messages {
		for _, c := range m.Content {
			if strings.Contains(c.Text, "SETTLE_NOW") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("\u6536\u5c3e\u63d0\u793a\u672a\u88ab\u6ce8\u5165\u5230\u5bf9\u8bdd")
	}
	if len(toolsSeen) < 2 {
		t.Fatalf("\u5e94\u81f3\u5c11 2 \u6b21\u6a21\u578b\u8c03\u7528(\u4e3b+\u6536\u5c3e)\uff0c\u5f97 %d", len(toolsSeen))
	}
	if !contains(toolsSeen[0], "Bash") {
		t.Fatalf("\u4e3b\u9636\u6bb5\u5e94\u80fd\u770b\u5230 Bash: %v", toolsSeen[0])
	}
	if contains(toolsSeen[1], "Bash") {
		t.Fatalf("\u6536\u5c3e\u9636\u6bb5\u5e94\u5c4f\u853d Bash: %v", toolsSeen[1])
	}
}

// With no Settlement, hitting the budget finishes immediately (unchanged behavior).
func TestNoSettlementFinishesImmediately(t *testing.T) {
	m := &scriptedModel{turns: [][]llm.StreamEvent{
		toolTurn("a", "Bash", `{"command":"echo 1"}`),
		toolTurn("b", "Bash", `{"command":"echo 2"}`),
	}}
	in := QueryInput{
		Tools:          tool.NewRegistry(tool.NewBash()),
		PermissionMode: permission.ModeBypass,
		WorkingDir:     t.TempDir(),
		MaxTurns:       1,
	}
	term := drain(t, in, QueryDeps{CallModel: m.call})
	if term.Reason != ReasonMaxTurns {
		t.Fatalf("reason=%v", term.Reason)
	}
	if m.calls != 1 {
		t.Fatalf("\u65e0\u6536\u5c3e\u5e94\u53ea\u8c03\u7528 1 \u6b21\u6a21\u578b\uff0c\u5f97 %d", m.calls)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
