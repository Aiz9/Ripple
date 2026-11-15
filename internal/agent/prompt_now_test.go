package agent

import (
	"strings"
	"testing"
	"time"
)

// TestChatNowVarRenders verifies the universal {{.Now}} runtime variable: a custom
// (chat) agent prompt referencing it renders the live server time each turn, rather
// than failing template execution and falling back to DefaultAssistantPrompt.
func TestChatNowVarRenders(t *testing.T) {
	prev := PromptOverride
	defer func() { PromptOverride = prev }()

	PromptOverride = func(key string) (string, bool) {
		if key == "tec_benchmark" {
			return "\u5f53\u524d\u65f6\u95f4\uff1a{{.Now}}", true
		}
		return "", false
	}

	out := chatSystem("tec_benchmark", "/app/data", "/tmp/x")
	if !strings.Contains(out, "\u5f53\u524d\u65f6\u95f4\uff1a") {
		t.Fatalf("custom prompt body missing, likely fell back to default: %q", out)
	}
	year := time.Now().Format("2006")
	if !strings.Contains(out, year) {
		t.Fatalf("{{.Now}} did not render the live time (want year %s): %q", year, out)
	}
}

// TestChatDataDirVarRenders verifies the universal {{.DataDir}} runtime variable:
// a custom prompt referencing it renders the server data root (s.m.dir), rather
// than failing template execution and falling back to DefaultAssistantPrompt.
func TestChatDataDirVarRenders(t *testing.T) {
	prev := PromptOverride
	defer func() { PromptOverride = prev }()

	PromptOverride = func(key string) (string, bool) {
		return "\u6570\u636e\u6839\u76ee\u5f55\uff1a{{.DataDir}}", true
	}

	out := chatSystem("tec_benchmark", "/app/data", "/tmp/x")
	if !strings.Contains(out, "\u6570\u636e\u6839\u76ee\u5f55\uff1a/app/data") {
		t.Fatalf("{{.DataDir}} did not render the data root: %q", out)
	}
}

// TestChatUnknownVarFallsBack verifies an out-of-catalog {{.X}} still degrades
// safely to the default assistant prompt (never a half-rendered prompt).
func TestChatUnknownVarFallsBack(t *testing.T) {
	prev := PromptOverride
	defer func() { PromptOverride = prev }()

	PromptOverride = func(key string) (string, bool) {
		return "\u5f15\u7528\u4e86\u4e0d\u5b58\u5728\u7684\u53d8\u91cf\uff1a{{.Bogus}}", true
	}

	out := chatSystem("whatever", "/app/data", "/tmp/x")
	if strings.Contains(out, "\u5f15\u7528\u4e86\u4e0d\u5b58\u5728\u7684\u53d8\u91cf") {
		t.Fatalf("broken template should have fallen back, got custom body: %q", out)
	}
	if !strings.Contains(out, DefaultAssistantPrompt) {
		t.Fatalf("expected fallback to DefaultAssistantPrompt, got: %q", out)
	}
}
