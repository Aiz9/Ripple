package llm

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"strings"
)

// geminiProvider uses the Gemini Developer REST API, including with a supplied
// HTTPClient so hosts can capture the original JSON/SSE bytes at the transport.
type geminiProvider struct{ cfg Config }

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}
type geminiPart struct {
	Text             *string       `json:"text,omitempty"`
	Thought          bool          `json:"thought,omitempty"`
	ThoughtSignature string        `json:"thoughtSignature,omitempty"`
	FunctionCall     *geminiCall   `json:"functionCall,omitempty"`
	FunctionResponse *geminiResult `json:"functionResponse,omitempty"`
}
type geminiCall struct {
	ID   string          `json:"id,omitempty"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}
type geminiResult struct {
	ID       string         `json:"id,omitempty"`
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}
type geminiThinking struct {
	IncludeThoughts bool   `json:"includeThoughts"`
	Budget          *int   `json:"thinkingBudget,omitempty"`
	Level           string `json:"thinkingLevel,omitempty"`
}
type geminiGeneration struct {
	MaxOutputTokens int             `json:"maxOutputTokens,omitempty"`
	Temperature     *float64        `json:"temperature,omitempty"`
	StopSequences   []string        `json:"stopSequences,omitempty"`
	ThinkingConfig  *geminiThinking `json:"thinkingConfig,omitempty"`
}
type geminiTool struct {
	Declarations []geminiDeclaration `json:"functionDeclarations"`
}
type geminiDeclaration struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}
type geminiRequest struct {
	Contents          []geminiContent  `json:"contents"`
	SystemInstruction *geminiContent   `json:"systemInstruction,omitempty"`
	Tools             []geminiTool     `json:"tools,omitempty"`
	GenerationConfig  geminiGeneration `json:"generationConfig"`
}

func validateGeminiConfig(cfg Config) error {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		// Don't echo URLs: a misconfigured URL may contain credentials.
		return fmt.Errorf("gemini: base URL must be an http(s) API root without credentials, query or fragment")
	}
	model := strings.TrimPrefix(cfg.Model, "models/")
	if model == "" || strings.ContainsAny(model, "/?#%:") || strings.ContainsAny(model, " \t\r\n") {
		return fmt.Errorf("gemini: model must be a model ID or models/<ID>")
	}
	if cfg.ThinkingType != "" && cfg.ThinkingType != "enabled" && cfg.ThinkingType != "disabled" {
		return fmt.Errorf("gemini: thinking type must be enabled, disabled or empty")
	}
	switch cfg.ReasoningEffort {
	case "", "minimal", "low", "medium", "high", "xhigh", "max":
	default:
		return fmt.Errorf("gemini: unsupported reasoning effort")
	}
	return nil
}

func (p *geminiProvider) thinking(req CompletionRequest) (*geminiThinking, error) {
	mode := p.cfg.ThinkingType
	if req.Thinking != "" {
		mode = req.Thinking
	}
	if mode != "" && mode != "enabled" && mode != "disabled" {
		return nil, fmt.Errorf("gemini: invalid request thinking override")
	}
	model := strings.TrimPrefix(p.cfg.Model, "models/")
	// Older non-thinking models must not receive thinkingConfig at all.
	budgetModel := strings.HasPrefix(model, "gemini-2.5-")
	levelModel := strings.HasPrefix(model, "gemini-3") || strings.HasPrefix(model, "gemini-4")
	if !budgetModel && !levelModel {
		if mode == "enabled" || p.cfg.ReasoningEffort != "" {
			return nil, fmt.Errorf("gemini: thinking controls require a Gemini 2.5, 3 or 4 model ID")
		}
		return nil, nil
	}
	t := &geminiThinking{IncludeThoughts: mode != "disabled"}
	if budgetModel {
		budget := -1 // dynamic; unset config still requests summaries
		if mode == "disabled" {
			budget = 0
			if strings.Contains(model, "pro") {
				budget = 128
			} // Pro cannot turn thinking off.
		} else {
			switch p.cfg.ReasoningEffort {
			case "minimal":
				budget = 512
			case "low":
				budget = 1024
			case "medium":
				budget = 8192
			case "high", "xhigh", "max":
				budget = 24576
			}
		}
		t.Budget = &budget
	} else {
		effort := p.cfg.ReasoningEffort
		if effort == "xhigh" || effort == "max" {
			effort = "high"
		}
		// These families cannot fully disable thinking. Use the lowest supported
		// level and suppress summaries; never send an invalid zero budget.
		if mode == "disabled" {
			effort = "low"
			if strings.Contains(model, "flash") && !strings.Contains(model, "3.8") {
				effort = "minimal"
			}
		}
		if effort == "minimal" && (!strings.Contains(model, "flash") || strings.Contains(model, "3.8")) {
			return nil, fmt.Errorf("gemini: minimal thinking is not supported by this model; use low")
		}
		t.Level = effort
	}
	return t, nil
}

func (p *geminiProvider) buildBody(req CompletionRequest) ([]byte, error) {
	thinking, err := p.thinking(req)
	if err != nil {
		return nil, err
	}
	body := geminiRequest{GenerationConfig: geminiGeneration{MaxOutputTokens: req.MaxTokens, Temperature: req.Temperature, StopSequences: req.Stop, ThinkingConfig: thinking}}
	if s := joinSystem(req.System); s != "" {
		body.SystemInstruction = &geminiContent{Parts: []geminiPart{{Text: &s}}}
	}
	calls := map[string]geminiCall{}
	appendParts := func(role string, parts []geminiPart) {
		if len(parts) == 0 {
			return
		}
		if n := len(body.Contents); n > 0 && body.Contents[n-1].Role == role {
			body.Contents[n-1].Parts = append(body.Contents[n-1].Parts, parts...)
		} else {
			body.Contents = append(body.Contents, geminiContent{Role: role, Parts: parts})
		}
	}
	for _, m := range req.Messages {
		role := "user"
		if m.Role == RoleAssistant {
			role = "model"
		}
		var parts []geminiPart
		for _, b := range m.Content {
			part := geminiPart{ThoughtSignature: b.Signature}
			switch b.Type {
			case BlockText:
				text := b.Text
				part.Text = &text
			case BlockThinking:
				// Signed parts must survive even when summaries are disabled.
				if b.Signature == "" {
					continue
				}
				part.Thought = true
				if b.Thinking != "" {
					text := b.Thinking
					part.Text = &text
				}
			case BlockToolUse:
				args := b.Input
				if len(args) == 0 {
					args = json.RawMessage("{}")
				}
				var obj map[string]any
				if json.Unmarshal(args, &obj) != nil || obj == nil {
					return nil, fmt.Errorf("gemini: tool arguments must be a JSON object")
				}
				// Generated IDs are local correlation IDs; native IDs must be echoed.
				call := geminiCall{Name: b.Name, Args: args}
				if !strings.HasPrefix(b.ID, "gemini-local-") {
					call.ID = b.ID
				}
				calls[b.ID] = call
				part.FunctionCall = &call
			case BlockToolResult:
				call, ok := calls[b.ToolUseID]
				if !ok {
					return nil, fmt.Errorf("gemini: tool result has no matching function call")
				}
				key := "output"
				if b.IsError {
					key = "error"
				}
				part.FunctionResponse = &geminiResult{ID: call.ID, Name: call.Name, Response: map[string]any{key: flattenText(b.Content)}}
			default:
				return nil, fmt.Errorf("gemini: unsupported content block type %q", b.Type)
			}
			parts = append(parts, part)
		}
		appendParts(role, parts)
	}
	if len(req.Tools) > 0 {
		tool := geminiTool{}
		for _, t := range req.Tools {
			schema, err := geminiSchema(t.InputSchema, t.InputSchema, 0)
			if err != nil {
				return nil, fmt.Errorf("gemini: tool %s schema: %w", t.Name, err)
			}
			tool.Declarations = append(tool.Declarations, geminiDeclaration{Name: t.Name, Description: t.Description, Parameters: schema})
		}
		body.Tools = []geminiTool{tool}
	}
	return json.Marshal(body)
}

// geminiSchema copies only the REST Schema subset. Property names are data,
// not schema keywords. Local refs are expanded before removing definitions;
// recursive/external refs fail clearly rather than silently weakening schemas.
func geminiSchema(schema, root map[string]any, depth int) (map[string]any, error) {
	if depth > 32 {
		return nil, fmt.Errorf("recursive or excessively deep schema")
	}
	out := map[string]any{}
	if ref, ok := schema["$ref"].(string); ok {
		if !strings.HasPrefix(ref, "#/") {
			return nil, fmt.Errorf("external schema references are unsupported")
		}
		var target any = root
		for _, key := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			m, ok := target.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid local schema reference")
			}
			target = m[strings.ReplaceAll(strings.ReplaceAll(key, "~1", "/"), "~0", "~")]
		}
		m, ok := target.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("unresolved local schema reference")
		}
		expanded, err := geminiSchema(m, root, depth+1)
		if err != nil {
			return nil, err
		}
		out = expanded
	}
	for key, value := range schema {
		switch key {
		case "properties":
			props, ok := value.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("properties must be an object")
			}
			clean := map[string]any{}
			for name, v := range props {
				m, ok := v.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("property schema must be an object")
				}
				s, err := geminiSchema(m, root, depth+1)
				if err != nil {
					return nil, err
				}
				clean[name] = s
			}
			out[key] = clean
		case "items":
			m, ok := value.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("tuple schemas are unsupported")
			}
			s, err := geminiSchema(m, root, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = s
		case "anyOf":
			raw, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			var variants []map[string]any
			if json.Unmarshal(raw, &variants) != nil {
				return nil, fmt.Errorf("invalid anyOf")
			}
			clean := []map[string]any{}
			for _, v := range variants {
				s, err := geminiSchema(v, root, depth+1)
				if err != nil {
					return nil, err
				}
				clean = append(clean, s)
			}
			out[key] = clean
		case "type":
			if t, ok := value.(string); ok {
				out[key] = strings.ToUpper(t)
			} else {
				return nil, fmt.Errorf("union type arrays are unsupported; use anyOf")
			}
		case "title", "description", "format", "nullable", "enum", "required", "minimum", "maximum", "minItems", "maxItems", "minProperties", "maxProperties", "minLength", "maxLength", "pattern", "propertyOrdering":
			out[key] = value
		}
	}
	return out, nil
}

func (p *geminiProvider) endpoint(stream bool) string {
	base := strings.TrimRight(p.cfg.BaseURL, "/")
	// Accept either a host root or an explicit versioned API root.
	u, _ := url.Parse(base)
	if u.Path == "" {
		base += "/v1beta"
	}
	endpoint := base + "/models/" + strings.TrimPrefix(p.cfg.Model, "models/")
	if stream {
		return endpoint + ":streamGenerateContent?alt=sse"
	}
	return endpoint + ":generateContent"
}
func (p *geminiProvider) request(ctx context.Context, req CompletionRequest, stream bool) (*http.Response, error) {
	body, err := p.buildBody(req)
	if err != nil {
		return nil, err
	}
	return doStream(ctx, p.cfg, p.endpoint(stream), body, func(r *http.Request) {
		r.Header.Set("content-type", "application/json")
		r.Header.Set("x-goog-api-key", p.cfg.APIKey)
		if stream {
			r.Header.Set("accept", "text/event-stream")
		} else {
			r.Header.Set("accept", "application/json")
		}
	}, "gemini")
}

type geminiUsage struct {
	Prompt     int `json:"promptTokenCount"`
	Candidates int `json:"candidatesTokenCount"`
	Thoughts   int `json:"thoughtsTokenCount"`
	Cached     int `json:"cachedContentTokenCount"`
}

func (u geminiUsage) norm() Usage {
	return Usage{InputTokens: u.Prompt, OutputTokens: u.Candidates + u.Thoughts, CacheReadTokens: u.Cached}
}

type geminiResponse struct {
	Candidates []struct {
		Content      geminiContent `json:"content"`
		FinishReason string        `json:"finishReason"`
		Index        int           `json:"index"`
	} `json:"candidates"`
	Usage          *geminiUsage `json:"usageMetadata"`
	PromptFeedback struct {
		BlockReason string `json:"blockReason"`
	} `json:"promptFeedback"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// One decoder is shared by Complete and Stream, keeping signatures, stop reasons
// and token accounting identical. Gemini's usage snapshots are cumulative.
type geminiDecoder struct {
	usage      Usage
	started    bool
	stop       string
	hasContent bool
	hasTool    bool
	callPrefix string
	callIndex  int
}

func (d *geminiDecoder) frame(raw []byte, yield func(StreamEvent, error) bool) bool {
	var r geminiResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		yield(StreamEvent{}, fmt.Errorf("gemini: malformed response/SSE JSON: %w", err))
		return false
	}
	if r.Error != nil {
		yield(StreamEvent{}, fmt.Errorf("gemini: %s", r.Error.Message))
		return false
	}
	if r.Usage != nil {
		u := r.Usage.norm()
		// A metadata-less initial chunk emits an empty start. Later snapshots may
		// correct input counts; only the positive difference is added downstream.
		delta := Usage{InputTokens: max(0, u.InputTokens-d.usage.InputTokens), OutputTokens: max(0, u.OutputTokens-d.usage.OutputTokens), CacheReadTokens: max(0, u.CacheReadTokens-d.usage.CacheReadTokens)}
		d.usage.Add(delta)
		if !d.started {
			if !yield(StreamEvent{Type: SEMessageStart, Usage: Usage{InputTokens: delta.InputTokens, CacheReadTokens: delta.CacheReadTokens}}, nil) {
				return false
			}
			d.started = true
			delta.InputTokens = 0
			delta.CacheReadTokens = 0
		}
		if delta != (Usage{}) && !yield(StreamEvent{Type: SEMessageDelta, Usage: delta}, nil) {
			return false
		}
	}
	if !d.started {
		if !yield(StreamEvent{Type: SEMessageStart}, nil) {
			return false
		}
		d.started = true
	}
	if r.PromptFeedback.BlockReason != "" {
		d.stop = "refusal"
		if !yield(StreamEvent{Type: SEMessageDelta, StopReason: d.stop}, nil) {
			return false
		}
		yield(StreamEvent{}, fmt.Errorf("gemini: prompt blocked (%s)", r.PromptFeedback.BlockReason))
		return false
	}
	for _, candidate := range r.Candidates {
		if candidate.Index != 0 {
			continue
		}
		switch candidate.FinishReason {
		case "":
		case "STOP":
			d.stop = "end_turn"
		case "MAX_TOKENS":
			d.stop = "max_tokens"
		case "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY":
			d.stop = "refusal"
			if !yield(StreamEvent{Type: SEMessageDelta, StopReason: d.stop}, nil) {
				return false
			}
			yield(StreamEvent{}, fmt.Errorf("gemini: response blocked (%s)", candidate.FinishReason))
			return false
		default:
			yield(StreamEvent{}, fmt.Errorf("gemini: unsupported finish reason %s", candidate.FinishReason))
			return false
		}
		for i, part := range candidate.Content.Parts {
			// Keep distinct wire parts distinct: a signature authenticates its
			// own part, so merging it with preceding unsigned text breaks replay.
			// The first part of a new SSE chunk may continue the previous one.
			if i > 0 && !yield(StreamEvent{Type: SEContentBlockStart}, nil) {
				return false
			}
			switch {
			case part.FunctionCall != nil:
				call := part.FunctionCall
				if call.Name == "" {
					yield(StreamEvent{}, fmt.Errorf("gemini: function call has no name"))
					return false
				}
				if d.callPrefix == "" {
					d.callPrefix = rand.Text()
				}
				id := call.ID
				if id == "" {
					id = fmt.Sprintf("gemini-local-%s-%d", d.callPrefix, d.callIndex)
				}
				d.callIndex++
				args := call.Args
				if len(args) == 0 {
					args = json.RawMessage("{}")
				}
				var obj map[string]any
				if json.Unmarshal(args, &obj) != nil || obj == nil {
					yield(StreamEvent{}, fmt.Errorf("gemini: function arguments must be an object"))
					return false
				}
				d.hasTool = true
				d.hasContent = true
				if !yield(StreamEvent{Type: SEToolUseStart, ToolID: id, ToolName: call.Name}, nil) {
					return false
				}
				if !yield(StreamEvent{Type: SEToolInputJSON, Text: string(args)}, nil) {
					return false
				}
			case part.Text != nil:
				kind := SETextDelta
				if part.Thought {
					kind = SEThinkingDelta
				}
				if *part.Text != "" {
					d.hasContent = true
					if !yield(StreamEvent{Type: kind, Text: *part.Text}, nil) {
						return false
					}
				}
			case part.ThoughtSignature != "": // signature-only final chunk
			default:
				yield(StreamEvent{}, fmt.Errorf("gemini: unsupported response part"))
				return false
			}
			if part.ThoughtSignature != "" && !yield(StreamEvent{Type: SEContentSignature, Text: part.ThoughtSignature}, nil) {
				return false
			}
		}
	}
	return true
}
func (d *geminiDecoder) finish(yield func(StreamEvent, error) bool) {
	if d.stop == "" {
		yield(StreamEvent{}, fmt.Errorf("gemini: incomplete response (missing finish reason)"))
		return
	}
	if !d.hasContent && d.stop != "max_tokens" {
		yield(StreamEvent{}, fmt.Errorf("gemini: empty response (no candidate content)"))
		return
	}
	stop := d.stop
	if d.hasTool && stop == "end_turn" {
		stop = "tool_use"
	}
	if yield(StreamEvent{Type: SEMessageDelta, StopReason: stop}, nil) {
		yield(StreamEvent{Type: SEMessageStop}, nil)
	}
}
func (p *geminiProvider) Stream(ctx context.Context, req CompletionRequest) iter.Seq2[StreamEvent, error] {
	return func(yield func(StreamEvent, error) bool) {
		resp, err := p.request(ctx, req, true)
		if err != nil {
			yield(StreamEvent{}, err)
			return
		}
		defer resp.Body.Close()
		scan := newSSEScanner(resp.Body)
		d := geminiDecoder{}
		for {
			_, data, err := scan.next()
			if err == io.EOF {
				d.finish(yield)
				return
			}
			if err != nil {
				yield(StreamEvent{}, fmt.Errorf("gemini: read SSE: %w", err))
				return
			}
			if strings.TrimSpace(data) == "" {
				continue
			}
			if !d.frame([]byte(data), yield) {
				return
			}
		}
	}
}
func (p *geminiProvider) Complete(ctx context.Context, req CompletionRequest) (Message, string, Usage, error) {
	resp, err := p.request(ctx, req, false)
	if err != nil {
		return Message{}, "", Usage{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return Message{}, "", Usage{}, err
	}
	acc := NewAccumulator()
	d := geminiDecoder{}
	emit := func(ev StreamEvent, e error) bool {
		if e != nil {
			err = e
			return false
		}
		acc.Add(ev)
		return true
	}
	if d.frame(raw, emit) {
		d.finish(emit)
	}
	return acc.Message(), acc.StopReason, acc.Usage, err
}
