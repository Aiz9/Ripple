package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

// dingTalkChannel implements DingTalk custom bots.
//
// Platform characteristics informing implementation:
//   - Per-bot 20/min limit can silently drop excess messages even with HTTP 200,
//     so rate-limit locally through DefaultRatePerMin.
//   - Security choices: signature, keywords, or IP allowlist. Only signatures are independent
//     of message content, so support signatures or completely unsecured bare Webhooks.
//   - HTTP 200 covers success and failure; inspect body errcode to avoid marking failures
//     delivered.
type dingTalkChannel struct{}

func (dingTalkChannel) Kind() string { return KindDingTalk }

func (dingTalkChannel) DefaultRatePerMin() int { return 20 }

// The Webhook URL contains access_token, making the entire URL a masked credential.
func (dingTalkChannel) SecretKeys() []string { return []string{"webhook", "secret"} }

// Changing the Webhook destination requires explicitly supplying the signing-secret choice again.
func (dingTalkChannel) DestinationKeys() []string { return []string{"webhook"} }

func (dingTalkChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("Missing webhook URL")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("Invalid webhook URL: %w", err)
	}
	return nil
}

// Send uses ActionCard with a button for one linked item, Markdown otherwise.
func (c dingTalkChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	hook := cfgString(cfg, "webhook")
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	endpoint, err := dingTalkSignedURL(hook, cfgString(cfg, "secret"), time.Now())
	if err != nil {
		return 0, Permanent(err)
	}

	title := markdownTitle(m)
	// Cap Markdown despite no clear platform byte limit to guard unusually large evidence fields.
	text, kept := markdownBody(m, 20000)

	var payload any
	if !m.Batch && len(m.Items) == 1 && m.Items[0].DetailURL != "" {
		payload = map[string]any{
			"msgtype": "actionCard",
			"actionCard": map[string]any{
				"title":          title,
				"text":           text,
				"btnOrientation": "0",
				"singleTitle":    "View details",
				"singleURL":      m.Items[0].DetailURL,
			},
		}
	} else {
		payload = map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]any{"title": title, "text": text},
		}
	}

	raw, err := doJSON(ctx, "POST", endpoint, nil, payload)
	if err != nil {
		return 0, err
	}
	// DingTalk embeds business errors inside HTTP 200 responses.
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("Failed to parse DingTalk response: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 301000 signature failure and 310000 keyword mismatch are configuration faults,
		// not self-healing retry conditions.
		return 0, Permanent(fmt.Errorf("DingTalk error %d: %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}

// dingTalkSignedURL appends timestamp/sign according to official rules.
//
// Sign timestamp + newline + secret using HMAC-SHA256 with secret as key;
// base64 then URL-encode. Timestamp uses milliseconds. Empty secret leaves URL unchanged
// for unsigned bots.
func dingTalkSignedURL(hook, secret string, now time.Time) (string, error) {
	if secret == "" {
		return hook, nil
	}
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + secret))
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	u, err := url.Parse(hook)
	if err != nil {
		// Do not expose url.Parse errors containing the full access-token-bearing URL.
		return "", fmt.Errorf("Failed to parse webhook URL: %s", redactRequestTarget(hook))
	}
	q := u.Query()
	q.Set("timestamp", ts)
	q.Set("sign", sign)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// validateHTTPURL checks supported schemes and blocks sensitive literal IP destinations.
//
// Two deliberate details:
//
//  1. Redact errors: url.Parse returns *url.Error containing the full original URL and embedded
//     DingTalk access_token, WeCom key, Telegram bot token, or Feishu hook ID.
//     Returning that error previously leaked credentials through configuration-test responses,
//     delivery last_error, server logs, and history APIs.
//     Keep all these outputs free of raw destination secrets.
//
//  2. Check literal IPs at save time for early feedback; domain addresses are checked at dial
//     time by blockInternalDial, the final enforcement point covering DNS rebinding.
//     Users should learn of invalid destinations before first delivery.
//
// Restrict schemes defensively; file/gopher and other protocols should never reach http.Client.
// Keep the destination protocol surface narrow.
func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("Address cannot be resolved (%s)", redactRequestTarget(raw))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("Only http/https supported; received %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("Missing hostname")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isBlockedDialIP(ip) && !allowLocalTargets() {
		return fmt.Errorf("Delivery to loopback/link-local address %s denied (set %s=1 if local delivery is required)", ip, AllowLocalTargetsEnv)
	}
	return nil
}
