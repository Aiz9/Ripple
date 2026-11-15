package agent

import (
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// TestLocalProviderFromEnv locks the local-LLM wiring: provider=local resolves to
// an OpenAI-compatible endpoint with no API key required (a placeholder key keeps
// the empty-key guard from disabling the engine), defaulting the base URL to the
// Ollama endpoint. This is what lets the whole pipeline run against an on-prem model.
func TestLocalProviderFromEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	t.Setenv("ANDROIDLAB_LLM_PROVIDER", "local")
	t.Setenv("ANDROIDLAB_LLM_MODEL", "qwen2.5-coder:7b")
	t.Setenv("ANDROIDLAB_LLM_BASE_URL", "")

	c, ok := FromEnv()
	if !ok {
		t.Fatal("FromEnv: local provider must resolve without an API key")
	}
	if c.Format != llm.FormatOpenAI {
		t.Fatalf("format=%v, want FormatOpenAI", c.Format)
	}
	if c.BaseURL != "http://localhost:11434/v1" {
		t.Fatalf("base_url=%q, want the Ollama default", c.BaseURL)
	}
	if c.Model != "qwen2.5-coder:7b" {
		t.Fatalf("model=%q, want the env model", c.Model)
	}
	if c.APIKey == "" {
		t.Fatal("APIKey must be a non-empty placeholder so the engine is not disabled")
	}
	if _, err := c.NewProvider(); err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
}

// TestLocalProviderConfigFrom locks the UI path: a full /chat/completions endpoint
// is normalized to the API base, and the empty key is filled with a placeholder.
func TestLocalProviderConfigFrom(t *testing.T) {
	c := ConfigFrom("local", "", "http://127.0.0.1:1234/v1/chat/completions", "", "")
	if c.Format != llm.FormatOpenAI {
		t.Fatalf("format=%v, want FormatOpenAI", c.Format)
	}
	if c.BaseURL != "http://127.0.0.1:1234/v1" {
		t.Fatalf("base_url=%q, want /chat/completions stripped", c.BaseURL)
	}
	if c.Model != "llama3.1" {
		t.Fatalf("model=%q, want the local default", c.Model)
	}
	if c.APIKey == "" {
		t.Fatal("APIKey must be a non-empty placeholder")
	}
}
