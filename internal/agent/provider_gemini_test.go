package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/internal/llmrec"
	"github.com/Autumn-27/norma/llm"
)

func TestGeminiConfigAndCapture(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	cfg := ConfigFrom("gemini", "gemini-2.5-flash", "", "", "")
	if cfg.Format != llm.FormatGemini || cfg.Provider() != "gemini" {
		t.Fatalf("cfg=%+v", cfg)
	}
	if _, err := cfg.NewProvider(); err == nil || !strings.Contains(err.Error(), "API key required") {
		t.Fatalf("missing key: %v", err)
	}
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{true: "stream", false: "complete"}[stream], func(t *testing.T) {
			atomic := `{"candidates":[{"content":{"parts":[{"text":"Hello"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,"thoughtsTokenCount":4,"cachedContentTokenCount":3}}`
			wire := atomic
			if stream {
				wire = "data: " + atomic + "\n\n"
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("x-goog-api-key") != "fixture-key" {
					t.Error("missing auth header")
				}
				io.WriteString(w, wire)
			}))
			defer srv.Close()
			cfg := ConfigFrom("gemini", "gemini-2.5-flash", srv.URL, "fixture-key", "")
			p, err := cfg.NewProvider()
			if err != nil {
				t.Fatal(err)
			}
			ctx, capture := llmrec.NewCapture(t.Context())
			req := llm.CompletionRequest{System: []string{"system"}, Messages: []llm.Message{llm.UserText("hello")}}
			if stream {
				a := llm.NewAccumulator()
				for ev, err := range p.Stream(ctx, req) {
					if err != nil {
						t.Fatal(err)
					}
					a.Add(ev)
				}
				if a.Usage.OutputTokens != 6 {
					t.Errorf("usage=%+v", a.Usage)
				}
			} else {
				_, _, u, err := p.Complete(ctx, req)
				if err != nil || u.OutputTokens != 6 {
					t.Fatalf("usage=%+v err=%v", u, err)
				}
			}
			if capture.RawResponse() != wire {
				t.Errorf("wire response changed: %q", capture.RawResponse())
			}
			if strings.Contains(capture.RawRequest(), "fixture-key") {
				t.Error("key leaked in capture")
			}
			var body map[string]any
			if err := json.Unmarshal([]byte(capture.RawRequest()), &body); err != nil || body["systemInstruction"] == nil || body["contents"] == nil {
				t.Errorf("request capture missing Gemini body: %s", capture.RawRequest())
			}
		})
	}
}

func TestGeminiFromEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "google-fixture")
	t.Setenv("ANDROIDLAB_LLM_PROVIDER", "gemini")
	t.Setenv("ANDROIDLAB_LLM_MODEL", "gemini-2.5-flash")
	c, ok := FromEnv()
	if !ok || c.Format != llm.FormatGemini || c.APIKey != "google-fixture" || c.Model != "gemini-2.5-flash" {
		t.Fatalf("environment did not resolve Gemini")
	}
	t.Setenv("GEMINI_API_KEY", "gemini-fixture")
	t.Setenv("ANDROIDLAB_LLM_PROVIDER", "")
	c, ok = FromEnv()
	if !ok || c.Format != llm.FormatGemini || c.APIKey != "gemini-fixture" {
		t.Fatal("inference or key precedence failed")
	}
	t.Setenv("ANDROIDLAB_LLM_MODEL", "")
	c, ok = FromEnv()
	if !ok {
		t.Fatal("missing key")
	}
	if _, err := c.NewProvider(); err == nil || !strings.Contains(err.Error(), "model is required") {
		t.Fatalf("model was defaulted: %v", err)
	}
	t.Setenv("ANDROIDLAB_LLM_PROVIDER", "gemini")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	c, ok = FromEnv()
	if !ok {
		t.Fatal("explicit Gemini selection was silently discarded")
	}
	if _, err := c.NewProvider(); err == nil || !strings.Contains(err.Error(), "API key required") {
		t.Fatalf("missing key: %v", err)
	}

}
