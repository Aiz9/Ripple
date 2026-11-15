package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/internal/agent"
	"github.com/Autumn-27/artex/internal/llmrec"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

func TestGeminiModelDiscovery(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models" || r.Header.Get("x-goog-api-key") != "fixture-key" || r.URL.Query().Get("key") != "" {
			t.Errorf("incorrect models request")
		}
		io.WriteString(w, `{"models":[{"name":"models/gemini-fixture","supportedGenerationMethods":["generateContent","countTokens"]},{"name":"models/embedding-fixture","supportedGenerationMethods":["embedContent"]}]}`)
	}))
	defer upstream.Close()
	body, _ := json.Marshal(map[string]string{"provider": "gemini", "base_url": upstream.URL, "api_key": "fixture-key"})
	rec := httptest.NewRecorder()
	s := &Server{}
	s.pgListModels(rec, httptest.NewRequest(http.MethodPost, "/api/llm/models", bytes.NewReader(body)))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"gemini-fixture"`) || strings.Contains(rec.Body.String(), "embedding-fixture") {
		t.Fatalf("models response: %d %s", rec.Code, rec.Body)
	}
}

func TestGeminiProfileRecording(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	pg := m.PG()
	if err := pg.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct{ name, model, key, base, want string }{
		{"no key", "gemini-2.5-flash", "", "", "API key required"},
		{"no model", "", "fixture-key", "", "model is required"},
		{"query key", "gemini-2.5-flash", "fixture-key", "https://example.test?key=secret", "without credentials"},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"name": "invalid-gemini", "format": "gemini", "model": invalid.model, "api_key": invalid.key, "base_url": invalid.base})
			s := &Server{m: m}
			rec := httptest.NewRecorder()
			s.pgSaveProfile(rec, httptest.NewRequest(http.MethodPost, "/api/llm/profiles", bytes.NewReader(body)))
			if rec.Code != 400 || !strings.Contains(rec.Body.String(), invalid.want) {
				t.Fatalf("invalid config: %d %s", rec.Code, rec.Body)
			}
		})
	}
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			atomic := `{"candidates":[{"content":{"parts":[{"text":"thinking","thought":true},{"functionCall":{"name":"lookup","args":{"query":"host"}},"thoughtSignature":"c2ln"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,"thoughtsTokenCount":4,"cachedContentTokenCount":3}}`
			wire := atomic
			if stream {
				wire = "data: " + atomic + "\n\n"
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, wire) }))
			defer upstream.Close()
			// Construct only the handler dependencies; startup would restore unrelated
			// task runtimes from the shared test DB and race temporary-directory cleanup.
			s := &Server{m: m, ctx: t.Context(), engine: NewEngine(m)}
			profileBody, _ := json.Marshal(map[string]any{"name": "gemini-recording-" + fmt.Sprint(stream), "format": "gemini", "model": "gemini-2.5-flash", "base_url": upstream.URL, "api_key": "fixture-key", "streaming": stream})
			rec := httptest.NewRecorder()
			s.pgSaveProfile(rec, httptest.NewRequest(http.MethodPost, "/api/llm/profiles", bytes.NewReader(profileBody)))
			if rec.Code != 200 {
				t.Fatalf("create Gemini profile: %d %s", rec.Code, rec.Body)
			}
			var saved struct {
				ID int64 `json:"id"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil {
				t.Fatal(err)
			}
			defer pg.Exec(`DELETE FROM llm_profiles WHERE id=$1`, saved.ID)
			cfg, ok := s.loadProfileConfig(saved.ID)
			if !ok || cfg.Format != llm.FormatGemini {
				t.Fatal("profile did not resolve Gemini")
			}
			inner, err := cfg.NewProvider()
			if err != nil {
				t.Fatal(err)
			}
			recorder := llmrec.Wrap(inner, pg, cfg.Model, "gemini-recording", "", "", func() bool { return true })
			session := transcript.NewSessionID()
			ctx := transcript.WithSessionID(t.Context(), session)
			req := llm.CompletionRequest{System: []string{"system"}, Messages: []llm.Message{llm.UserText("lookup")}, Tools: []llm.ToolSchema{{Name: "lookup", InputSchema: map[string]any{"type": "object"}}}}
			if stream {
				a := llm.NewAccumulator()
				for ev, err := range recorder.Stream(ctx, req) {
					if err != nil {
						t.Fatal(err)
					}
					a.Add(ev)
				}
				if a.Usage != (llm.Usage{InputTokens: 10, OutputTokens: 6, CacheReadTokens: 3}) {
					t.Errorf("usage=%+v", a.Usage)
				}
			} else {
				_, _, _, err := recorder.Complete(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
			}
			var id int64
			if err := pg.QueryRow(`SELECT id FROM llm_records WHERE session_id=$1 ORDER BY id DESC LIMIT 1`, session).Scan(&id); err != nil {
				t.Fatal(err)
			}
			got, err := pg.GetLLMRecord(id)
			if err != nil {
				t.Fatal(err)
			}
			if got.RawResponse != wire || !strings.Contains(got.RawRequest, "functionDeclarations") || !strings.Contains(got.RawRequest, "systemInstruction") {
				t.Fatalf("wire bodies lost: %+v", got)
			}
			if strings.Contains(got.RawRequest, "fixture-key") || strings.Contains(got.RequestBody, "fixture-key") {
				t.Fatal("key leaked in recording")
			}
			if got.InputTokens != 10 || got.OutputTokens != 6 {
				t.Errorf("record token counts: %+v", got)
			}
			var input, output, cached int
			if err := pg.QueryRow(`SELECT input_tokens,output_tokens,cache_read FROM llm_usage WHERE profile_name='gemini-recording' ORDER BY id DESC LIMIT 1`).Scan(&input, &output, &cached); err != nil {
				t.Fatal(err)
			}
			if input != 10 || output != 6 || cached != 3 {
				t.Errorf("usage ledger=%d/%d/%d", input, output, cached)
			}
		})
	}
}

func TestGeminiProfileMissingKey(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	cfg := agent.ConfigFrom("gemini", "gemini-2.5-flash", "", "", "")
	if _, err := cfg.NewProvider(); err == nil {
		t.Fatal("keyless Gemini profile accepted")
	}
}
