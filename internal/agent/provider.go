// Package agent wires real LLM-driven planner and work agents (on top of the
// agent-core SDK) to the dual SQLite graph. See the architecture guide in docs.
// §4.3 (planner) and §4.4 (work agent).
//
// Provider configuration is read from the environment so the system runs with
// any Anthropic- or OpenAI-format endpoint. If no key is configured, FromEnv
// returns ok=false and the exploration engine stays idle (an LLM is required).
package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Aiz9/ripple/internal/llmrec"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/transcript"
)

// Config describes the LLM backend resolved from the environment.
type Config struct {
	Format  llm.Format
	BaseURL string
	APIKey  string
	Model   string
	// Proxy routes all LLM requests through the given proxy URL (http/https/socks5,
	// optionally with user:pass@ credentials). Empty means direct — it does NOT
	// fall back to the standard *_PROXY environment variables.
	Proxy string
	// RatePerSecond / RatePerMinute cap the shared request rate across ALL agents
	// using the provider (0 = that window unlimited).
	RatePerSecond float64
	RatePerMinute float64
	// ContextWindowK is the model's context window in K tokens (user-configured),
	// used to size compaction thresholds. 0 = default; see CompactionWindow.
	ContextWindowK int
	// ThinkingType independently controls thinking.type:
	//   empty omits it (default, compatible with unsupported models); disabled turns it off;
	//   enabled turns it on. It is independent of ReasoningEffort: some APIs lack thinking
	//   and activate reasoning through effort alone, so either can be configured separately.
	ThinkingType string
	// ReasoningEffort independently controls reasoning intensity:
	//   empty omits it; low/medium/high/xhigh/max select the corresponding intensity.
	//   OpenAI uses top-level reasoning_effort; Anthropic uses output_config.effort.
	ReasoningEffort string
	// Stream selects streaming SSE (true, default) or genuine non-streaming (false):
	// stream:false returns complete JSON through Provider.Complete, avoiding gateways with
	// broken SSE (empty frames or missing reasoning chunks), at the cost of live progress and
	// token counts. Maps to agentcore.Options.NonStreaming = !Stream.
	Stream bool
	// MaxTokens caps per-reply output tokens; 0 omits the field for the server default,
	// preserving historical behavior. ContextWindowK is the total capacity used locally for
	// compaction thresholds and is never sent; this cap is sent with every request as Options.MaxTokens.
	MaxTokens int
	// MaxTokensField chooses the request field name for format=openai:
	//   empty uses max_tokens (default); max_completion_tokens selects the newer field.
	// OpenAI reasoning models (o-series/GPT-5) reject max_tokens with unsupported_parameter,
	// while many gateways require it; let users choose per endpoint rather than infer automatically.
	MaxTokensField string
	// SessionHeaderKey optionally names a custom HTTP header carrying the current session ID
	// (chat: conv-<id>; worker: exp<x>-worker-i<intent>; see WorkerSessionID), for gateways
	// using session IDs for prompt caching or sticky routing.
	// Empty omits the header. transcript.WithSessionID adds the value to request context and
	// RoundTripper reads it, allowing one shared provider to send session-specific values.
	SessionHeaderKey string
	// Retry is the resolved profile retry configuration: profile override -> global policy ->
	// built-in defaults, resolved by the server. See RetryConfig; zero uses all built-in defaults.
	Retry RetryConfig
}

// RetryConfig travels with an LLM profile. Attempt-count semantics at every layer:
// 0 uses defaults; negative disables retries; positive sets the count. Interval semantics:
// 0 uses existing exponential backoff; positive uses that fixed duration.
type RetryConfig struct {
	// ConnectAttempts/ConnectInterval: SDK pre-stream connection retries for reset/timeout/429/5xx,
	// mapping to llm.Config.MaxRetries/RetryInterval; default 3, exponential 0.5s up to 8s.
	ConnectAttempts int
	ConnectInterval time.Duration
	// EmptyAttempts/EmptyInterval: SDK completed-but-empty-content retries (OpenAI only), mapping
	// to llm.Config.EmptyResponseRetries/EmptyResponseInterval.
	// Default 2 with the same exponential schedule.
	EmptyAttempts int
	EmptyInterval time.Duration
	// StreamAttempts/StreamInterval: additional same-provider safe-window retries above the SDK,
	// replaying broken/overloaded/in-stream-429 calls only before any output reaches the caller.
	// Handled in server/task_llm.go; default 2, exponential 0.5s up to 4s.
	StreamAttempts int
	StreamInterval time.Duration
}

// compaction window resolution bounds (in K tokens). Below the floor the
// threshold math (window − summary reserve − buffer) would go non-positive and
// compaction would fire every turn; above the cap it would never fire.
const (
	defaultWindowK = 200  // unset → assume a 200K window (Claude default)
	minWindowK     = 32   // floor so effectiveWindow stays comfortably positive
	maxWindowK     = 1000 // cap at 1M tokens (user request)
)

// CompactionWindow returns the model context window in TOKENS for compaction
// thresholds, resolved from the user-configured size (ContextWindowK). 0/unset →
// a 200K default; otherwise clamped to [32K, 1M] so compaction stays effective.
func (c Config) CompactionWindow() int {
	k := c.ContextWindowK
	if k <= 0 {
		k = defaultWindowK
	}
	if k < minWindowK {
		k = minWindowK
	}
	if k > maxWindowK {
		k = maxWindowK
	}
	return k * 1000
}

// compactionConfig builds the agent-core compaction config for a context window
// in tokens. agentcore.NewSession wires the summarizer (same provider) when this
// is set on Options.Compaction.
func compactionConfig(windowTokens int) *compaction.Config {
	if windowTokens <= 0 {
		windowTokens = defaultWindowK * 1000
	}
	return &compaction.Config{ContextWindow: windowTokens}
}

// FromEnv resolves the LLM provider config:
//
//	ANDROIDLAB_LLM_PROVIDER = anthropic|openai|openai-responses|gemini|local (default: inferred from keys)
//	ANDROIDLAB_LLM_MODEL    = model id        (default: per provider)
//	ANDROIDLAB_LLM_BASE_URL = endpoint        (optional; required-ish for local, default Ollama)
//	ANDROIDLAB_LLM_PROXY    = proxy URL        (optional; http/https/socks5)
//	ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY (or GOOGLE_API_KEY) = credentials
//
// provider=local targets a self-hosted OpenAI-compatible server (Ollama,
// llama.cpp, LM Studio, vLLM) and needs no API key: the whole pipeline then runs
// against an on-prem model with no third-party calls. Point ANDROIDLAB_LLM_BASE_URL
// at the server's /v1 (default http://localhost:11434/v1) and set ANDROIDLAB_LLM_MODEL
// to a pulled model. OPENAI_API_KEY, if set, is forwarded (some gateways require it).
func FromEnv() (Config, bool) {
	prov := os.Getenv("ANDROIDLAB_LLM_PROVIDER")
	anthKey := os.Getenv("ANTHROPIC_API_KEY")
	oaiKey := os.Getenv("OPENAI_API_KEY")
	geminiKey := geminiAPIKey()

	if prov == "" {
		switch {
		case anthKey != "":
			prov = "anthropic"
		case oaiKey != "":
			prov = "openai"
		case geminiKey != "":
			prov = "gemini"
		default:
			return Config{}, false
		}
	}

	c := Config{
		BaseURL: os.Getenv("ANDROIDLAB_LLM_BASE_URL"),
		Model:   os.Getenv("ANDROIDLAB_LLM_MODEL"),
		Proxy:   strings.TrimSpace(os.Getenv("ANDROIDLAB_LLM_PROXY")),
		// Streaming by default; ANDROIDLAB_LLM_STREAM=false/0/off explicitly selects non-streaming.
		Stream: !isFalsy(os.Getenv("ANDROIDLAB_LLM_STREAM")),
	}
	switch prov {
	case "gemini":
		c.Format = llm.FormatGemini
		c.APIKey = geminiKey
	case "openai":
		c.Format = llm.FormatOpenAI
		c.APIKey = oaiKey
		if c.Model == "" {
			c.Model = "gpt-4o"
		}
	case "openai-responses":
		c.Format = llm.FormatOpenAIResponses
		c.APIKey = oaiKey
		if c.Model == "" {
			c.Model = "gpt-5"
		}
	case "local":
		// Self-hosted OpenAI-compatible server (Ollama/llama.cpp/LM Studio/vLLM).
		// No key required; keep any OPENAI_API_KEY the user set (some gateways need it),
		// otherwise use a placeholder so the empty-key guard below doesn't disable the engine.
		c.Format = llm.FormatOpenAI
		if c.BaseURL == "" {
			c.BaseURL = "http://localhost:11434/v1" // Ollama default
		}
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/chat/completions"), "/")
		c.APIKey = oaiKey
		if c.APIKey == "" {
			c.APIKey = "local"
		}
		if c.Model == "" {
			c.Model = "llama3.1"
		}
	default:
		c.Format = llm.FormatAnthropic
		c.APIKey = anthKey
		if c.Model == "" {
			c.Model = "claude-opus-4-8"
		}
	}
	// An explicit Gemini selection must reach NewProvider so a missing key
	// produces a clear startup error rather than silently disabling the engine.
	if c.APIKey == "" && c.Format != llm.FormatGemini {
		return Config{}, false
	}
	return c, true
}

// ConfigFrom builds a Config from UI-provided strings (provider defaults to
// anthropic; model defaults per provider). Inputs are trimmed and the base URL
// is normalized to the API base the provider expects (the provider appends the
// endpoint path itself), so a full endpoint URL is tolerated.
func ConfigFrom(provider, model, baseURL, apiKey, proxy string) Config {
	c := Config{
		Model:   strings.TrimSpace(model),
		BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		APIKey:  strings.TrimSpace(apiKey),
		Proxy:   strings.TrimSpace(proxy),
		Stream:  true, // Streaming default, overridable by caller profile.
	}
	switch strings.TrimSpace(provider) {
	case "gemini":
		c.Format = llm.FormatGemini
		if c.APIKey == "" {
			c.APIKey = geminiAPIKey()
		}
	case "openai":
		c.Format = llm.FormatOpenAI
		// provider appends "/chat/completions"; tolerate a full endpoint URL.
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/chat/completions"), "/")
		if c.Model == "" {
			c.Model = "gpt-4o"
		}
	case "openai-responses":
		c.Format = llm.FormatOpenAIResponses
		// provider appends "/responses"; tolerate a full endpoint URL.
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/responses"), "/")
		if c.Model == "" {
			c.Model = "gpt-5"
		}
	case "local":
		// Self-hosted OpenAI-compatible server; no key required.
		c.Format = llm.FormatOpenAI
		if c.BaseURL == "" {
			c.BaseURL = "http://localhost:11434/v1"
		}
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/chat/completions"), "/")
		if c.APIKey == "" {
			c.APIKey = "local"
		}
		if c.Model == "" {
			c.Model = "llama3.1"
		}
	default:
		c.Format = llm.FormatAnthropic
		// provider appends "/v1/messages".
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/v1/messages"), "/")
		if c.Model == "" {
			c.Model = "claude-opus-4-8"
		}
	}
	return c
}

func geminiAPIKey() string {
	if key := strings.TrimSpace(os.Getenv("GEMINI_API_KEY")); key != "" {
		return key
	}
	return strings.TrimSpace(os.Getenv("GOOGLE_API_KEY"))
}

// isFalsy reports whether an env-var string explicitly requests "off". Empty or
// unrecognized → false (so an unset var keeps the streaming default).
func isFalsy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "false", "off", "no":
		return true
	}
	return false
}

// Provider returns the short provider name ("anthropic"/"openai").
func (c Config) Provider() string {
	switch c.Format {
	case llm.FormatGemini:
		return "gemini"
	case llm.FormatOpenAI:
		return "openai"
	case llm.FormatOpenAIResponses:
		return "openai-responses"
	}
	return "anthropic"
}

// NewProvider builds an llm.Provider from the config. When a rate is set, the
// limiter lives on the single provider instance — so planner + all workers +
// main agent (which share this provider) are bounded by one shared rate limit.
func (c Config) NewProvider() (llm.Provider, error) {
	client, err := quotaAwareHTTPClient(c.Proxy, c.SessionHeaderKey)
	if err != nil {
		return nil, err
	}
	lc := llm.Config{
		Format:     c.Format,
		BaseURL:    c.BaseURL,
		APIKey:     c.APIKey,
		Model:      c.Model,
		HTTPClient: client,
	}
	// Forward thinking switch and effort independently; empty omits the respective field.
	// Either, both, or neither may be sent.
	lc.ThinkingType = c.ThinkingType
	lc.ReasoningEffort = c.ReasoningEffort
	// Choose output-limit field name (empty=max_tokens). Its value arrives per turn through
	// agentcore.Options.MaxTokens; the provider only selects the destination key.
	lc.MaxTokensField = c.MaxTokensField
	// Forward SDK-compatible retry semantics unchanged: counts 0/default, negative/off; intervals 0/exponential.
	lc.MaxRetries = c.Retry.ConnectAttempts
	lc.RetryInterval = c.Retry.ConnectInterval
	lc.EmptyResponseRetries = c.Retry.EmptyAttempts
	lc.EmptyResponseInterval = c.Retry.EmptyInterval
	if c.RatePerSecond > 0 || c.RatePerMinute > 0 {
		lc.RateLimit = &llm.RateLimit{PerSecond: c.RatePerSecond, PerMinute: c.RatePerMinute}
	}
	return llm.NewProvider(lc)
}

// IsQuotaExhaustedMessage deliberately recognizes only explicit balance,
// billing, credit, or quota-exhaustion signals. Generic 429/rate-limit text,
// authentication failures, network errors, and server failures are excluded.
var nonFailoverHTTPStatus = regexp.MustCompile(`(?:status(?:\s+code)?|http(?:\s+status)?)\s*[=:]?\s*(?:401|403|5\d\d)\b`)
var transientQuotaLimit = regexp.MustCompile(`(?i)(?:\b(?:rpm|tpm|rpd|qps)\b|quota[_\s-]*metric|rate[_\s-]*limit|too many requests|(?:requests?|tokens?)\s+(?:per|/)\s*(?:second|minute)|(?:per|/)\s*(?:second|minute)\s+(?:requests?|tokens?)|generate[_\s-]*requests[_\s-]*per[_\s-]*(?:minute|second)|tokens?[_\s-]*per[_\s-]*(?:minute|second))`)

func IsQuotaExhaustedMessage(message string) bool {
	message = strings.ToLower(message)
	// Authentication/authorization and provider-side 5xx failures never rotate,
	// even when a gateway happens to echo a quota-looking phrase in the body.
	if nonFailoverHTTPStatus.MatchString(message) {
		return false
	}
	// Provider APIs frequently describe an ordinary rate limit as "quota
	// exceeded", especially Google-style responses containing a quota metric.
	// These limits recover with time and must stay on the current provider.
	if transientQuotaLimit.MatchString(message) {
		return false
	}
	markers := []string{
		"insufficient_quota", "quota_exceeded", "quota exceeded", "quota exhausted",
		"exceeded your current quota", "billing_hard_limit_reached",
		"billing hard limit", "billing_not_active", "credit balance", "insufficient credit",
		"insufficient balance", "balance is too low", "payment required", "status 402",
		// Preserve provider-supplied Chinese balance/quota/billing error markers.
		"\u4f59\u989d\u4e0d\u8db3", "\u989d\u5ea6\u4e0d\u8db3", "\u989d\u5ea6\u5df2\u7528\u5c3d", "\u6b20\u8d39",
	}
	for _, marker := range markers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	// gRPC RESOURCE_EXHAUSTED is overloaded for both account quota and ordinary
	// request-rate limiting. Preserve it as an explicit exhaustion signal only
	// when the same error does not identify a transient rate limit.
	return strings.Contains(message, "resource_exhausted") &&
		!strings.Contains(message, "rate limit") &&
		!strings.Contains(message, "too many requests")
}

// quotaAwareTransport preserves Norma's normal retry behavior except for a 429
// whose body explicitly says the account quota/balance is exhausted. Norma's
// retry loop treats every 429 as transient; normalizing only that response to
// 402 lets a task router fail over immediately while retaining the original
// response body for provider-specific classification and audit logs.
type quotaAwareTransport struct {
	base http.RoundTripper
	// sessionHeaderKey, when non-empty, is the HTTP header name each request
	// carries; its value is the session id read from the request context. Empty
	// disables it. See Config.SessionHeaderKey.
	sessionHeaderKey string
}

func (t quotaAwareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Custom session-id header: name is user-configured, value is THIS run's
	// session id (norma stashes it on the context via transcript.WithSessionID).
	// Stable across a session's turns and distinct across sessions — exactly what
	// a session-keyed prompt cache wants. Skipped when no session id is present.
	if t.sessionHeaderKey != "" {
		if sid := transcript.SessionIDFrom(req.Context()); sid != "" {
			req.Header.Set(t.sessionHeaderKey, sid)
		}
	}
	// When LLM recording is on, the Recorder puts a Capture on the context so the
	// raw wire bodies can be persisted. This is the only layer that still sees
	// them: norma builds the request body internally and decodes the SSE response
	// before either reaches the recorder.
	capt := llmrec.CaptureFrom(req.Context())
	capt.SetRequest(requestBodySnapshot(req))

	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	// Tee rather than read: a 200 is an SSE stream that must keep streaming. The
	// 429 branch below reads through this wrapper, so its body lands in the
	// capture before being replaced.
	resp.Body = capt.TeeResponse(resp.StatusCode, resp.Body)

	if resp.StatusCode != http.StatusTooManyRequests {
		return resp, nil
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	if readErr != nil {
		return resp, nil
	}
	if IsQuotaExhaustedMessage(string(body)) {
		resp.StatusCode = http.StatusPaymentRequired
		resp.Status = "402 Payment Required"
	}
	return resp, nil
}

// requestBodySnapshot copies an outgoing request body without consuming it.
// norma builds every model request from a *bytes.Reader, so net/http populates
// GetBody and the copy has no effect on what gets sent.
func requestBodySnapshot(req *http.Request) string {
	if req.GetBody == nil {
		return ""
	}
	rc, err := req.GetBody()
	if err != nil {
		return ""
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return ""
	}
	return string(b)
}

func quotaAwareHTTPClient(proxy, sessionHeaderKey string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		transport.Proxy = nil // Empty means direct, without falling back to HTTP_PROXY/HTTPS_PROXY.
	} else {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("llm: invalid proxy %q: %w", proxy, err)
		}
		switch proxyURL.Scheme {
		case "http", "https", "socks5":
		case "":
			return nil, fmt.Errorf("llm: proxy %q missing scheme (use http://, https:// or socks5://)", proxy)
		default:
			return nil, fmt.Errorf("llm: unsupported proxy scheme %q (use http, https or socks5)", proxyURL.Scheme)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{Transport: quotaAwareTransport{base: transport, sessionHeaderKey: strings.TrimSpace(sessionHeaderKey)}}, nil
}

// logTestConnection prints the raw HTTP status code(s) and response body of a
// connection test to the server log, so clicking Test leaves a diagnosable trail of
// exactly what the gateway returned — 401 bodies, quota text, empty frames — not
// just the collapsed ok/err the UI shows. Bodies are clipped to keep a chatty
// SSE stream from flooding the log.
func logTestConnection(c Config, capt *llmrec.Capture) {
	attempts := capt.Attempts()
	if len(attempts) == 0 {
		log.Printf("[llm-test] %s / %s @ %s -- no HTTP request sent (configuration parsing or connection failed)",
			c.Provider(), c.Model, c.BaseURL)
		return
	}
	for i, a := range attempts {
		log.Printf("[llm-test] %s / %s @ %s -- attempt %d/%d HTTP %d\nResponse body: %s",
			c.Provider(), c.Model, c.BaseURL, i+1, len(attempts), a.Status, clipBody(a.Body))
	}
}

// clipBody trims a wire body for logging. 4K is plenty to show an error JSON or
// the head of an SSE stream while bounding a runaway response.
func clipBody(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(empty)"
	}
	const max = 4096
	if len(s) > max {
		return s[:max] + fmt.Sprintf("...(truncated, %d bytes total)", len(s))
	}
	return s
}

// TestConnection makes a minimal real completion to verify the provider/model/
// endpoint/key actually work. Returns the round-trip latency and the model's
// reply text.
func TestConnection(ctx context.Context, c Config) (time.Duration, string, error) {
	prov, err := c.NewProvider()
	if err != nil {
		return 0, "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Capture raw wire responses so connection tests reveal gateway status codes and bodies,
	// otherwise lost after norma decodes them into StreamEvents. quotaAwareTransport reads this
	// Capture from context and records every HTTP attempt's status and body.
	ctx, capt := llmrec.NewCapture(ctx)
	defer logTestConnection(c, capt)
	// Connection tests are one-shot and bypass the agentcore session loop, so ctx otherwise has
	// no session ID. Endpoints with SessionHeaderKey (opencode zen requires x-opencode-session)
	// return 400 MissingSessionID without it, even when normal conversations work.
	// Attach a one-off random session ID so tests use the same header logic as real conversations.
	// Endpoints without SessionHeaderKey ignore it, with no side effects.
	ctx = transcript.WithSessionID(ctx, "conntest-"+transcript.NewSessionID())
	start := time.Now()
	// Allow enough MaxTokens for reasoning models (for example deepseek-v4-pro), which may spend
	// about 2900 tokens even on ping before answering. A cap of 32 truncates reasoning with
	// finish=length; the connection may succeed (err=nil) but display an interrupted/length/resume
	// result. A sufficient budget lets the model output OK and finish=stop.
	// Keep EscalateMaxTokens false to avoid cap increases and wasteful resume loops after truncation.
	reply, err := agentcore.Run(ctx, agentcore.Options{
		Provider:       prov,
		SystemPrompt:   []string{"You are a connection test. Output exactly OK. Do not reason, explain, or add anything else."},
		PermissionMode: acperm.ModeBypass,
		MaxTurns:       1,
		MaxTokens:      8192,
		NonStreaming:   !c.Stream, // Test with the profile's actual streaming/non-streaming mode.
	}, "ping")
	lat := time.Since(start)
	if err != nil {
		return lat, "", err
	}
	// err==nil is insufficient: reasoning can exhaust the budget, policy can suppress text, or
	// compatibility layers can drop content. Such profiles give no visible reply in conversations;
	// mark the connection test failed whenever no visible content exists.
	reply = strings.TrimSpace(reply)
	if reply == "" {
		return lat, "", fmt.Errorf("Model returned no reply content (request succeeded but no text was returned)")
	}
	return lat, reply, nil
}
