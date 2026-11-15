package notify

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Channel adapters must be stateless: multiple channel configurations share one instance
// concurrently, passing credentials only through cfg.
type Channel interface {
	// Kind returns the registry-matching channel identifier.
	Kind() string
	// Validate checks required fields/formats at save time. Errors are user-visible, so identify
	// specific missing fields instead of saying only invalid configuration.
	Validate(cfg map[string]any) error
	// Send returns the number of items actually delivered and any error.
	//
	// Platforms limit message length, potentially truncating digest members. Marking every member
	// delivered would silently lose omitted findings while history still reported success.
	// Returning kept lets callers mark only the first kept items delivered and leave the remainder
	// for another batch.
	//
	// Errors mean delivery failed; *PermanentError means do not retry.
	// On failure kept is meaningless and must be ignored.
	Send(ctx context.Context, cfg map[string]any, m Message) (int, error)
	// DefaultRatePerMin supplies the platform-recommended per-minute cap for new channels;
	// 0 means no known limit.
	DefaultRatePerMin() int
	// SecretKeys names credentials masked in API responses; masked values in updates preserve
	// existing secrets. Only the adapter knows which fields are credentials (WeCom's whole URL
	// versus DingTalk's secret), so upper layers must not guess.
	// Channel implementations own this knowledge.
	SecretKeys() []string
	// DestinationKeys names fields controlling where messages go.
	//
	// Destinations and credentials are separate security-sensitive sets. Allowing destination-only
	// edits while retaining stored credentials lets configuration editors exfiltrate real secrets
	// to their own server, defeating response masking.
	// See PrepareConfigUpdate.
	DestinationKeys() []string
}

// Explicit registry literals centralize all channels instead of init side effects, making
// missing additions visible at compile time rather than runtime.
var registry = map[string]Channel{
	KindDingTalk: dingTalkChannel{},
	KindFeishu:   feishuChannel{},
	KindWeCom:    weComChannel{},
	KindWebhook:  webhookChannel{},
	KindTelegram: telegramChannel{},
	KindEmail:    emailChannel{},
}

// Get returns an adapter by kind.
func Get(kind string) (Channel, bool) {
	c, ok := registry[kind]
	return c, ok
}

// ValidKind reports supported channel kinds.
func ValidKind(kind string) bool {
	_, ok := registry[kind]
	return ok
}

// Kinds lists supported identifiers lexically for stable UI dropdown order.
func Kinds() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PermanentError marks failures that should not retry: bad credentials, refusal, invalid body, etc.
// Retries help transient network/rate-limit/5xx faults; repeating permanent failures cannot
// succeed and hides the real cause in retry logs.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent wraps errors as permanent; nil stays nil, allowing
// return Permanent(someCheck()).
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{Err: err}
}

// IsPermanent checks the error chain for a permanent-failure marker.
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// Configuration-reading helpers.
//
// JSONB decoded to map[string]any represents numbers as float64 and arrays as []any.
// These helpers centralize conversion and tolerate UI-induced type variations,
// such as ports submitted as strings.

// cfgString reads and trims strings, often padded by form copy/paste.
func cfgString(cfg map[string]any, key string) string {
	v, ok := cfg[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// cfgInt accepts JSON float64 or string integers.
func cfgInt(cfg map[string]any, key string) int {
	switch v := cfg[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

// cfgBool also accepts string true/1.
func cfgBool(cfg map[string]any, key string) bool {
	switch v := cfg[key].(type) {
	case bool:
		return v
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		return s == "true" || s == "1" || s == "yes"
	default:
		return false
	}
}

// cfgStrings trims string-array values and drops empties.
func cfgStrings(cfg map[string]any, key string) []string {
	raw, ok := cfg[key].([]any)
	if !ok {
		// Also accepts a single string for one-value form submissions.
		if s := cfgString(cfg, key); s != "" {
			return []string{s}
		}
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// cfgMap trims map keys/values and drops empty keys (for example custom HTTP headers).
func cfgMap(cfg map[string]any, key string) map[string]string {
	raw, ok := cfg[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		out[k] = s
	}
	return out
}
