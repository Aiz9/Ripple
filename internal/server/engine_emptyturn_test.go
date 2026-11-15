package server

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// Detect/continue reasoning-only idle turns; see steerHooks.Stop.

func assistantThinking(text string) llm.Message {
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockThinking, Thinking: text, Signature: "sig"},
	}}
}

func TestIsThinkingOnlyTurn(t *testing.T) {
	toolUse := llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockThinking, Thinking: "\u5148\u626b\u7aef\u53e3"},
		{Type: llm.BlockToolUse, ID: "t1", Name: "run_nuclei"},
	}}
	cases := []struct {
		name string
		msgs []llm.Message
		want bool
	}{
		{"thinking only", []llm.Message{llm.UserText("\u5f00\u59cb"), assistantThinking("\u60f3\u60f3")}, true},
		{"thinking+tool", []llm.Message{llm.UserText("\u5f00\u59cb"), toolUse}, false},
		{"thinking+text", []llm.Message{assistantThinking("\u60f3\u60f3"), {
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{{Type: llm.BlockThinking, Thinking: "x"}, llm.TextBlock("\u7ed3\u8bba")},
		}}, false},
		{"text is whitespace only", []llm.Message{{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{{Type: llm.BlockThinking, Thinking: "x"}, llm.TextBlock("  \n ")},
		}}, true},
		{"completely empty assistant turn", []llm.Message{{Role: llm.RoleAssistant}}, true},
		// Tool results have user role; inspect the preceding assistant rather than nearest message.
		{"last message is a tool result", []llm.Message{toolUse, {
			Role:    llm.RoleUser,
			Content: []llm.ContentBlock{{Type: llm.BlockToolResult, ToolUseID: "t1"}},
		}}, false},
		{"no assistant message", []llm.Message{llm.UserText("\u5f00\u59cb")}, false},
		{"empty history", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isThinkingOnlyTurn(c.msgs); got != c.want {
				t.Fatalf("isThinkingOnlyTurn = %v, want %v", got, c.want)
			}
		})
	}
}

// fakeHooks is programmable to verify respect for inner HookRunner decisions.
type fakeHooks struct {
	prevent  bool
	blocking []string
	msg      string
}

func (f fakeHooks) PreToolUse(context.Context, string, []byte) (bool, string, []byte) {
	return false, "", nil
}
func (f fakeHooks) PostToolUse(context.Context, string, []byte, []byte, bool) {}
func (f fakeHooks) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return f.prevent, f.blocking, f.msg
}

func TestSteerHooksStopNudgesEmptyTurn(t *testing.T) {
	empty := []llm.Message{assistantThinking("\u6211\u5e94\u8be5\u5148\u679a\u4e3e\u5b50\u57df\u540d")}

	t.Run("idle turn injects a continuation instruction", func(t *testing.T) {
		h := steerHooks{nudges: &atomic.Int64{}, limit: defaultEmptyTurnNudges, label: "worker-1 · #1"}
		prevent, blocking, _ := h.Stop(context.Background(), empty)
		if prevent {
			t.Fatal("an idle turn must not hard-stop")
		}
		if len(blocking) != 1 || blocking[0] != emptyTurnNudge {
			t.Fatalf("blocking = %v, want [emptyTurnNudge]", blocking)
		}
	})

	t.Run("does not intervene when there is text or a tool call", func(t *testing.T) {
		h := steerHooks{nudges: &atomic.Int64{}, limit: defaultEmptyTurnNudges}
		normal := []llm.Message{{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{llm.TextBlock("\u5df2\u5b8c\u6210\u626b\u63cf\uff0c\u672a\u53d1\u73b0\u5f00\u653e\u7aef\u53e3")},
		}}
		if _, blocking, _ := h.Stop(context.Background(), normal); blocking != nil {
			t.Fatalf("a normal finish was misjudged as idle: %v", blocking)
		}
		if n := h.nudges.Load(); n != 0 {
			t.Fatalf("no count when not intervening, got %d", n)
		}
	})

	t.Run("allows finishing after reaching the limit", func(t *testing.T) {
		const limit = 5 // User configured five empty-response retries.
		h := steerHooks{nudges: &atomic.Int64{}, limit: limit}
		for i := 1; i <= limit; i++ {
			if _, blocking, _ := h.Stop(context.Background(), empty); len(blocking) != 1 {
				t.Fatalf("attempt %d should still be within quota, blocking = %v", i, blocking)
			}
		}
		if _, blocking, _ := h.Stop(context.Background(), empty); blocking != nil {
			t.Fatalf("still injecting past the limit: %v", blocking)
		}
	})

	// Negative empty-response retries disables nudges, resolving to zero.
	t.Run("does not intervene when disabled", func(t *testing.T) {
		h := steerHooks{nudges: &atomic.Int64{}, limit: 0}
		if _, blocking, _ := h.Stop(context.Background(), empty); blocking != nil {
			t.Fatalf("still injecting while disabled: %v", blocking)
		}
	})

	t.Run("inner does not stack when it decides to hard-stop", func(t *testing.T) {
		h := steerHooks{inner: fakeHooks{prevent: true, msg: "guard \u62d2\u7edd\u6536\u573a"}, nudges: &atomic.Int64{}, limit: defaultEmptyTurnNudges}
		prevent, blocking, msg := h.Stop(context.Background(), empty)
		if !prevent || msg != "guard \u62d2\u7edd\u6536\u573a" || blocking != nil {
			t.Fatalf("inner hard stop was rewritten: prevent=%v blocking=%v msg=%q", prevent, blocking, msg)
		}
		if n := h.nudges.Load(); n != 0 {
			t.Fatalf("yielding to inner must not consume quota, got %d", n)
		}
	})

	t.Run("inner does not stack when it already wants to continue", func(t *testing.T) {
		h := steerHooks{inner: fakeHooks{blocking: []string{"guard \u7684\u7eed\u8dd1\u7406\u7531"}}, nudges: &atomic.Int64{}, limit: defaultEmptyTurnNudges}
		_, blocking, _ := h.Stop(context.Background(), empty)
		if len(blocking) != 1 || blocking[0] != "guard \u7684\u7eed\u8dd1\u7406\u7531" {
			t.Fatalf("inner continuation message was rewritten: %v", blocking)
		}
	})

	t.Run("behavior unchanged without a counter", func(t *testing.T) {
		h := steerHooks{limit: defaultEmptyTurnNudges} // For example a future caller forgetting to pass nudges.
		if _, blocking, _ := h.Stop(context.Background(), empty); blocking != nil {
			t.Fatalf("must not inject without a counter: %v", blocking)
		}
	})
}
