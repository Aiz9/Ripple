package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func geminiFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/gemini/" + name + ".sse")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func geminiTestProvider(t *testing.T, h http.HandlerFunc) Provider {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	p, err := NewProvider(Config{Format: FormatGemini, BaseURL: srv.URL, APIKey: "fixture-secret", Model: "gemini-2.5-flash", RetryInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Both wire paths use the same fixture responses; SSE snapshots also exercise
// repeated cumulative usage, independent of the number of text/tool chunks.
func TestGeminiResponses(t *testing.T) {
	tests := []struct {
		name, fixture, atomic, text, stop, think string
		output                                   int
		wantErr                                  string
	}{
		{name: "plain", fixture: "plain", atomic: `{"candidates":[{"content":{"parts":[{"text":"Hello"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,"cachedContentTokenCount":3}}`, text: "Hello", stop: "end_turn", output: 2},
		{name: "thinking", fixture: "thinking", atomic: `{"candidates":[{"content":{"parts":[{"text":"Let me think.","thought":true},{"text":"Hello"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,"thoughtsTokenCount":4,"cachedContentTokenCount":3}}`, text: "Hello", think: "Let me think.", stop: "end_turn", output: 6},
		{name: "tool", fixture: "tool", atomic: `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"lookup","args":{"query":"host"}},"thoughtSignature":"c2lnbmF0dXJl"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,"thoughtsTokenCount":4,"cachedContentTokenCount":3}}`, stop: "tool_use", output: 6},
		{name: "safety", atomic: `{"candidates":[{"finishReason":"SAFETY"}],"usageMetadata":{"promptTokenCount":10}}`, stop: "refusal", wantErr: "blocked"},
		{name: "prompt safety", atomic: `{"promptFeedback":{"blockReason":"SAFETY"}}`, stop: "refusal", wantErr: "prompt blocked"},
		{name: "empty", atomic: `{"candidates":[]}`, wantErr: "incomplete response"},
		{name: "malformed", atomic: `{"candidates":`, wantErr: "malformed"},
		{name: "max tokens", atomic: `{"candidates":[{"content":{"parts":[{"text":"partial"}]},"finishReason":"MAX_TOKENS"}]}`, text: "partial", stop: "max_tokens"},
		{name: "truncated", atomic: `{"candidates":[{"content":{"parts":[{"text":"partial"}]}}]}`, wantErr: "incomplete"},
	}
	for _, tt := range tests {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%v", tt.name, stream), func(t *testing.T) {
				p := geminiTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("x-goog-api-key") != "fixture-secret" || strings.Contains(r.URL.String(), "fixture-secret") {
						t.Error("missing header key or key leaked in URL")
					}
					suffix := ":generateContent"
					if stream {
						suffix = ":streamGenerateContent"
						if r.URL.Query().Get("alt") != "sse" {
							t.Error("missing alt=sse")
						}
					}
					if r.URL.Path != "/v1beta/models/gemini-2.5-flash"+suffix {
						t.Errorf("path=%s", r.URL.Path)
					}
					if stream {
						w.Header().Set("content-type", "text/event-stream")
						if tt.fixture != "" {
							io.WriteString(w, geminiFixture(t, tt.fixture))
						} else {
							fmt.Fprintf(w, "data: %s\n\n", tt.atomic)
						}
					} else {
						io.WriteString(w, tt.atomic)
					}
				})
				req := CompletionRequest{Messages: []Message{UserText("hello")}}
				var msg Message
				var stop string
				var usage Usage
				var err error
				if stream {
					a := NewAccumulator()
					for ev, e := range p.Stream(t.Context(), req) {
						if e != nil {
							err = e
							break
						}
						a.Add(ev)
					}
					msg, stop, usage = a.Message(), a.StopReason, a.Usage
				} else {
					msg, stop, usage, err = p.Complete(t.Context(), req)
				}
				if tt.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
						t.Fatalf("err=%v want %s", err, tt.wantErr)
					}
					if tt.stop != "" && stop != tt.stop {
						t.Errorf("stop=%q", stop)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if msg.Text() != tt.text || stop != tt.stop {
					t.Fatalf("msg=%+v stop=%s", msg, stop)
				}
				if tt.fixture != "" && usage != (Usage{InputTokens: 10, OutputTokens: tt.output, CacheReadTokens: 3}) {
					t.Errorf("usage=%+v", usage)
				}
				if tt.think != "" && (len(msg.Content) < 2 || msg.Content[0].Thinking != tt.think) {
					t.Errorf("thinking=%+v", msg)
				}
				if tt.stop == "tool_use" {
					calls := msg.ToolUses()
					if len(calls) != 1 || calls[0].Signature != "c2lnbmF0dXJl" || calls[0].ID == "" || string(calls[0].Input) != `{"query":"host"}` {
						t.Errorf("calls=%+v", calls)
					}
				}
			})
		}
	}
}

func TestGeminiToolRoundTrip(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			round := 0
			p := geminiTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
				round++
				raw, _ := io.ReadAll(r.Body)
				var body geminiRequest
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Error(err)
				}
				if round == 1 {
					if stream {
						io.WriteString(w, geminiFixture(t, "tool"))
					} else {
						io.WriteString(w, `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"lookup","args":{"query":"host"}},"thoughtSignature":"c2lnbmF0dXJl"}]},"finishReason":"STOP"}]}`)
					}
					return
				}
				if len(body.Contents) != 3 || body.Contents[1].Role != "model" || body.Contents[2].Role != "user" {
					t.Errorf("grouping=%+v", body.Contents)
					return
				}
				call := body.Contents[1].Parts[0]
				result := body.Contents[2].Parts[0]
				if call.ThoughtSignature != "c2lnbmF0dXJl" || result.FunctionResponse == nil || result.FunctionResponse.Name != "lookup" || result.FunctionResponse.Response["output"] != "found" {
					t.Errorf("history=%s", raw)
				}
				if call.FunctionCall.ID != "" || result.FunctionResponse.ID != "" {
					t.Error("local ID leaked into Gemini wire")
				}
				if stream {
					io.WriteString(w, geminiFixture(t, "plain"))
				} else {
					io.WriteString(w, `{"candidates":[{"content":{"parts":[{"text":"Hello"}]},"finishReason":"STOP"}]}`)
				}
			})
			req := CompletionRequest{Messages: []Message{UserText("lookup")}}
			invoke := func() Message {
				t.Helper()
				if !stream {
					m, _, _, err := p.Complete(t.Context(), req)
					if err != nil {
						t.Fatal(err)
					}
					return m
				}
				a := NewAccumulator()
				for ev, err := range p.Stream(t.Context(), req) {
					if err != nil {
						t.Fatal(err)
					}
					a.Add(ev)
				}
				return a.Message()
			}
			m := invoke()
			req.Messages = append(req.Messages, m, Message{Role: RoleUser, Content: []ContentBlock{ToolResultText(m.ToolUses()[0].ID, "found", false)}})
			if invoke().Text() != "Hello" {
				t.Error("missing answer")
			}
		})
	}
}

func TestGeminiBuildBody(t *testing.T) {
	temp := 0.3
	schema := map[string]any{"type": "object", "additionalProperties": false, "$schema": "schema", "$defs": map[string]any{"arg": map[string]any{"type": "string"}}, "properties": map[string]any{"additionalProperties": map[string]any{"$ref": "#/$defs/arg"}}, "required": []string{"additionalProperties"}}
	original, _ := json.Marshal(schema)
	p := geminiProvider{cfg: Config{Model: "gemini-2.5-flash", ThinkingType: "enabled", ReasoningEffort: "high"}}
	req := CompletionRequest{System: []string{"system", "instructions"}, Messages: []Message{UserText("one"), UserText("two")}, Tools: []ToolSchema{{Name: "lookup", InputSchema: schema}}, MaxTokens: 100, Temperature: &temp, Stop: []string{"END"}, Thinking: "disabled"}
	raw, err := p.buildBody(req)
	if err != nil {
		t.Fatal(err)
	}
	var b geminiRequest
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if *b.SystemInstruction.Parts[0].Text != "system\n\ninstructions" || len(b.Contents) != 1 || len(b.Contents[0].Parts) != 2 {
		t.Fatalf("body=%s", raw)
	}
	if *b.GenerationConfig.ThinkingConfig.Budget != 0 || b.GenerationConfig.ThinkingConfig.IncludeThoughts {
		t.Errorf("disabled override ignored: %s", raw)
	}
	if b.GenerationConfig.MaxOutputTokens != 100 || *b.GenerationConfig.Temperature != temp || !reflect.DeepEqual(b.GenerationConfig.StopSequences, []string{"END"}) {
		t.Error("generation fields lost")
	}
	params := b.Tools[0].Declarations[0].Parameters
	if params["additionalProperties"] != nil || params["$schema"] != nil || params["$defs"] != nil {
		t.Error("unsupported schema keywords retained")
	}
	prop := params["properties"].(map[string]any)["additionalProperties"].(map[string]any)
	if prop["type"] != "STRING" || prop["$ref"] != nil {
		t.Errorf("reference not expanded: %v", prop)
	}
	after, _ := json.Marshal(schema)
	if string(original) != string(after) {
		t.Error("schema mutated")
	}
}

func TestGeminiThinking(t *testing.T) {
	tests := []struct {
		model, mode, effort, override, level string
		budget                               int
		hasBudget, summary                   bool
	}{
		{model: "gemini-2.5-flash", mode: "enabled", effort: "low", budget: 1024, hasBudget: true, summary: true},
		{model: "gemini-2.5-flash", mode: "enabled", effort: "high", override: "disabled", hasBudget: true, budget: 0},
		{model: "gemini-2.5-pro", override: "disabled", hasBudget: true, budget: 128},
		{model: "gemini-3-pro-preview", effort: "max", level: "high", summary: true},
		{model: "gemini-3-pro-preview", override: "disabled", level: "low"},
		{model: "gemini-3-flash-preview", override: "disabled", level: "minimal"},
		{model: "gemini-4-argon", override: "disabled", level: "low"},
	}
	for _, tt := range tests {
		t.Run(tt.model+tt.mode+tt.override, func(t *testing.T) {
			p := geminiProvider{cfg: Config{Model: tt.model, ThinkingType: tt.mode, ReasoningEffort: tt.effort}}
			got, err := p.thinking(CompletionRequest{Thinking: tt.override})
			if err != nil {
				t.Fatal(err)
			}
			if got.Level != tt.level || got.IncludeThoughts != tt.summary || (got.Budget != nil) != tt.hasBudget || (got.Budget != nil && *got.Budget != tt.budget) {
				t.Errorf("thinking=%+v", got)
			}
		})
	}
}

func TestGeminiHTTPFailures(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, status := range []int{401, 403, 429, 500, 503} {
			t.Run(fmt.Sprintf("%d/%v", status, stream), func(t *testing.T) {
				attempts := 0
				p := geminiTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
					attempts++
					if attempts == 1 || status == 401 || status == 403 {
						w.WriteHeader(status)
						io.WriteString(w, `{"error":{"message":"fixture failure"}}`)
						return
					}
					if stream {
						io.WriteString(w, geminiFixture(t, "plain"))
					} else {
						io.WriteString(w, `{"candidates":[{"content":{"parts":[{"text":"OK"}]},"finishReason":"STOP"}]}`)
					}
				})
				var err error
				if stream {
					for _, e := range p.Stream(t.Context(), CompletionRequest{}) {
						if e != nil {
							err = e
						}
					}
				} else {
					_, _, _, err = p.Complete(t.Context(), CompletionRequest{})
				}
				if status == 401 || status == 403 {
					if err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) || attempts != 1 {
						t.Fatalf("err=%v attempts=%d", err, attempts)
					}
				} else if err != nil || attempts != 2 {
					t.Fatalf("err=%v attempts=%d", err, attempts)
				}
			})
		}
	}
}

func TestGeminiConfig(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	cfg := Config{Format: FormatGemini, Model: "gemini-2.5-flash"}
	if _, err := NewProvider(cfg); err == nil || !strings.Contains(err.Error(), "API key required") {
		t.Fatalf("missing key: %v", err)
	}
	t.Setenv("GOOGLE_API_KEY", "google-fixture")
	p, err := NewProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p.(*geminiProvider).cfg.APIKey != "google-fixture" {
		t.Error("missing fallback")
	}
	t.Setenv("GEMINI_API_KEY", "gemini-fixture")
	p, err = NewProvider(cfg)
	if err != nil || p.(*geminiProvider).cfg.APIKey != "gemini-fixture" {
		t.Fatal("wrong key precedence")
	}
	cfg.Model = ""
	if _, err := NewProvider(cfg); err == nil {
		t.Error("missing model accepted")
	}
	cfg.Model = "gemini-2.5-flash"
	cfg.BaseURL = "https://example.test?key=do-not-print"
	if _, err := NewProvider(cfg); err == nil || strings.Contains(err.Error(), "do-not-print") {
		t.Fatalf("URL validation: %v", err)
	}
}

func TestGeminiCancellationAndEarlyStop(t *testing.T) {
	p := geminiTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `data: {"promptFeedback":{"blockReason":"SAFETY"}}`+"\n\n")
	})
	// The iterator must not call yield again after the consumer stops at an event.
	for range p.Stream(t.Context(), CompletionRequest{}) {
		break
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, _, err := p.Complete(ctx, CompletionRequest{}); err == nil {
		t.Error("cancelled request succeeded")
	}
}

func TestGeminiSignatureOnlyChunk(t *testing.T) {
	a := NewAccumulator()
	d := geminiDecoder{}
	emit := func(ev StreamEvent, err error) bool {
		if err != nil {
			t.Fatal(err)
		}
		a.Add(ev)
		return true
	}
	for _, raw := range []string{`{"candidates":[{"content":{"parts":[{"text":"answer"}]}}]}`, `{"candidates":[{"content":{"parts":[{"thoughtSignature":"opaque"}]},"finishReason":"STOP"}]}`} {
		if !d.frame([]byte(raw), emit) {
			t.Fatal("decode stopped")
		}
	}
	d.finish(emit)
	m := a.Message()
	if len(m.Content) != 1 || m.Content[0].Signature != "opaque" {
		t.Errorf("signature lost: %+v", m)
	}
}

func TestGeminiParallelToolHistory(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprint(native), func(t *testing.T) {
			id1, id2 := "", ""
			if native {
				id1, id2 = "native-one", "native-two"
			}
			raw := fmt.Sprintf(`{"candidates":[{"content":{"parts":[{"functionCall":{"id":%q,"name":"first","args":{}},"thoughtSignature":"signed-first"},{"functionCall":{"id":%q,"name":"second","args":{}},"thoughtSignature":"signed-second"}]},"finishReason":"STOP"}]}`, id1, id2)
			a := NewAccumulator()
			d := geminiDecoder{}
			emit := func(ev StreamEvent, err error) bool {
				if err != nil {
					t.Fatal(err)
				}
				a.Add(ev)
				return true
			}
			if !d.frame([]byte(raw), emit) {
				t.Fatal("decode failed")
			}
			d.finish(emit)
			m := a.Message()
			calls := m.ToolUses()
			if len(calls) != 2 || calls[0].ID == calls[1].ID {
				t.Fatalf("correlation IDs: %+v", calls)
			}
			if calls[0].Signature != "signed-first" || calls[1].Signature != "signed-second" {
				t.Fatalf("signatures: %+v", calls)
			}
			p := geminiProvider{cfg: Config{Model: "gemini-2.5-flash"}}
			body, err := p.buildBody(CompletionRequest{Messages: []Message{UserText("tools"), m, {Role: RoleUser, Content: []ContentBlock{ToolResultText(calls[0].ID, "ok", false)}}, {Role: RoleUser, Content: []ContentBlock{ToolResultText(calls[1].ID, "failed", true)}}, UserText("continue")}})
			if err != nil {
				t.Fatal(err)
			}
			var req geminiRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatal(err)
			}
			if len(req.Contents) != 3 || len(req.Contents[2].Parts) != 3 {
				t.Fatalf("grouping=%s", body)
			}
			first, second := req.Contents[2].Parts[0].FunctionResponse, req.Contents[2].Parts[1].FunctionResponse
			if first.Name != "first" || second.Name != "second" || second.Response["error"] != "failed" || first.ID != id1 || second.ID != id2 {
				t.Fatalf("results=%s", body)
			}
		})
	}
}

func TestGeminiSchemaErrors(t *testing.T) {
	for name, schema := range map[string]map[string]any{
		"external ref":   {"$ref": "https://example.test/schema"},
		"recursive ref":  {"$ref": "#/$defs/node", "$defs": map[string]any{"node": map[string]any{"$ref": "#/$defs/node"}}},
		"unresolved ref": {"$ref": "#/$defs/missing"},
		"union type":     {"type": []string{"string", "null"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := geminiSchema(schema, schema, 0); err == nil {
				t.Fatal("unsupported schema accepted")
			}
		})
	}
}

func TestGeminiUsageCorrections(t *testing.T) {
	a := NewAccumulator()
	d := geminiDecoder{}
	emit := func(ev StreamEvent, err error) bool {
		if err != nil {
			t.Fatal(err)
		}
		a.Add(ev)
		return true
	}
	frames := []string{
		`{"candidates":[{"content":{"parts":[{"text":"hello"}]}}]}`,
		`{"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,"thoughtsTokenCount":3,"cachedContentTokenCount":2}}`,
		`{"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":3,"thoughtsTokenCount":4,"cachedContentTokenCount":3}}`,
		`{"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":3,"thoughtsTokenCount":4,"cachedContentTokenCount":3}}`,
	}
	for _, raw := range frames {
		if !d.frame([]byte(raw), emit) {
			t.Fatal("decode failed")
		}
	}
	d.finish(emit)
	if a.Usage != (Usage{InputTokens: 12, OutputTokens: 7, CacheReadTokens: 3}) {
		t.Fatalf("usage double counted: %+v", a.Usage)
	}
}

func TestGeminiSignedPartBoundaries(t *testing.T) {
	a := NewAccumulator()
	d := geminiDecoder{}
	emit := func(ev StreamEvent, err error) bool {
		if err != nil {
			t.Fatal(err)
		}
		a.Add(ev)
		return true
	}
	raw := `{"candidates":[{"content":{"parts":[{"text":"unsigned"},{"text":"signed","thoughtSignature":"opaque"},{"text":"after"}]},"finishReason":"STOP"}]}`
	if !d.frame([]byte(raw), emit) {
		t.Fatal("decode failed")
	}
	d.finish(emit)
	m := a.Message()
	if len(m.Content) != 3 || m.Content[0].Signature != "" || m.Content[1].Text != "signed" || m.Content[1].Signature != "opaque" || m.Content[2].Signature != "" {
		t.Fatalf("signed parts merged: %+v", m)
	}
}
