package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// weComMarkdownLimit is a hard byte limit, not a character limit.
// Tightest among six channels and the main reason TruncateBytes exists.
const weComMarkdownLimit = 4096

// weComChannel implements WeCom group bots.
//
// Platform characteristics:
//   - URL key is the sole credential; no signatures.
//   - Markdown content above 4096 bytes is rejected, not truncated. Three-byte CJK leaves
//     only around a thousand characters, requiring client-side truncation.
//   - 20/min limit also needs local enforcement.
type weComChannel struct{}

func (weComChannel) Kind() string { return KindWeCom }

func (weComChannel) DefaultRatePerMin() int { return 20 }

// Entire Webhook URL is the complete credential, with no separate signing fields
// needing masking.
func (weComChannel) SecretKeys() []string { return []string{"webhook"} }

// Webhook is both destination and credential, so address edits leave no separate old secrets.
func (weComChannel) DestinationKeys() []string { return []string{"webhook"} }

func (weComChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("Missing webhook URL")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("Invalid webhook URL: %w", err)
	}
	return nil
}

func (c weComChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	// Digest lists easily exceed 4096 bytes even at 50 one-line findings.
	// Truncate locally: rejection loses the whole batch, while partial packing delivers some items.
	content, kept := markdownBody(m, weComMarkdownLimit)
	payload := map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]any{"content": content},
	}
	raw, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("Failed to parse WeCom response: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 45009 is a rolling rate limit; retry after backoff is useful, so keep it retryable.
		// Reaching it suggests rate_per_min is too aggressive; retries are fallback,
		// while lowering the configured rate is the real correction.
		if res.ErrCode == 45009 {
			return 0, fmt.Errorf("WeCom rate limit %d: %s", res.ErrCode, res.ErrMsg)
		}
		// 93000 is an invalid Webhook key, permanently failing until configuration changes.
		return 0, Permanent(fmt.Errorf("WeCom error %d: %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}
