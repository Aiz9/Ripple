package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// feishuChannel implements Feishu/Lark custom bots with interactive cards.
//
// Platform characteristics:
// - Signature differs from DingTalk and is easy to confuse; see feishuSign.
// - Business failure is code!=0 inside HTTP 200.
// - Card header colors reflect severity for easy list scanning.
type feishuChannel struct{}

func (feishuChannel) Kind() string { return KindFeishu }

// Feishu bot limit is approximately 5/second, mapped here to 100/minute.
func (feishuChannel) DefaultRatePerMin() int { return 100 }

// Last Webhook path component uniquely identifies the bot and is a credential.
func (feishuChannel) SecretKeys() []string { return []string{"webhook", "secret"} }

// Destination edits require an explicit new signing-secret choice.
func (feishuChannel) DestinationKeys() []string { return []string{"webhook"} }

func (feishuChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("Missing webhook URL")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("Invalid webhook URL: %w", err)
	}
	return nil
}

func (c feishuChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	card, kept := feishuCard(m)
	payload := map[string]any{
		"msg_type": "interactive",
		"card":     card,
	}
	// Signature fields live alongside message fields, only when secret is configured.
	if secret := cfgString(cfg, "secret"); secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		payload["timestamp"] = ts
		payload["sign"] = feishuSign(ts, secret)
	}
	raw, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		// Support alternative field names used by some hook versions.
		StatusCode    int    `json:"StatusCode"`
		StatusMessage string `json:"StatusMessage"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("Failed to parse Feishu response: %w (%s)", err, snippet(raw))
	}
	if res.Code != 0 {
		return 0, Permanent(fmt.Errorf("Feishu error %d: %s", res.Code, res.Msg))
	}
	if res.StatusCode != 0 {
		return 0, Permanent(fmt.Errorf("Feishu error %d: %s", res.StatusCode, res.StatusMessage))
	}
	return kept, nil
}

// feishuSign follows the official signature algorithm.
//
// Important: the official example uses
//
//	hmac.new(string_to_sign.encode(), digestmod=sha256)
//
// key = timestamp + newline + secret and an empty message, not
// key=secret/message=stringToSign as DingTalk does. The algorithms are inverted;
// copying the other platform fails signature verification with 19021.
func feishuSign(timestamp, secret string) string {
	stringToSign := timestamp + "\n" + secret
	mac := hmac.New(sha256.New, []byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// feishuSeverityTemplate maps severity to card-header color.
// Unknown uses grey, not blue, to avoid confusion with low.
func feishuSeverityTemplate(severity string) string {
	switch severity {
	case "critical":
		return "red"
	case "high":
		return "orange"
	case "medium":
		return "yellow"
	case "low":
		return "blue"
	default:
		return "grey"
	}
}

// feishuMaxCardBytes conservatively bounds content below the platform limit, including
// JSON-wrapper overhead, because oversize rejects the whole card.
const feishuMaxCardBytes = 24000

// feishuCard returns the card and number of items actually packed.
// Like markdownBody, only kept items may be marked delivered.
func feishuCard(m Message) (map[string]any, int) {
	elements := []any{}
	kept := 0
	if m.Batch {
		// Pack whole items before building the header; remaining-count wording must use
		// the actual number fitting in the card.
		kept = packItemCount(m.Items, feishuMaxCardBytes, markdownReservedBytes, "", byteSize, func(it Item, idx int) string {
			return feishuBatchLine(it, idx+1)
		})
		items := m.Items[:kept]
		elements = append(elements, feishuMarkdownDiv(markdownBatchIntro(m, items, len(m.Items))))
		for i, it := range items {
			elements = append(elements, feishuMarkdownDiv(feishuBatchLine(it, i+1)))
		}
		if m.HomeURL != "" {
			elements = append(elements, feishuButton("View all in ARTEX", m.HomeURL))
		}
	} else if len(m.Items) > 0 {
		kept = 1
		it := m.Items[0]
		elements = append(elements, feishuMarkdownDiv(feishuItemLines(it)))
		if it.DetailURL != "" {
			elements = append(elements, feishuButton("View details", it.DetailURL))
		}
	}

	card := map[string]any{
		"config":   map[string]any{"wide_screen_mode": true},
		"header":   map[string]any{"title": map[string]any{"tag": "plain_text", "content": markdownTitle(m)}},
		"elements": elements,
	}
	if len(m.Items) > 0 {
		card["header"].(map[string]any)["template"] = feishuSeverityTemplate(m.Items[0].Severity)
	}
	return card, kept
}

func feishuMarkdownDiv(content string) map[string]any {
	return map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": content}}
}

func feishuButton(label, url string) map[string]any {
	return map[string]any{
		"tag": "action",
		"actions": []any{map[string]any{
			"tag":  "button",
			"text": map[string]any{"tag": "lark_md", "content": label},
			"url":  url,
			"type": "primary",
		}},
	}
}

// feishuItemLines renders one finding as lark_md.
//
// lark_md parses links/emphasis like Markdown; pass all external fields through markdownText
// for single-line escaping, preventing finding titles from injecting clickable external links.
// Keep untrusted text inert.
func feishuItemLines(it Item) string {
	out := fmt.Sprintf("**%s · %s**", SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if it.IsStatusChange() {
		out += fmt.Sprintf("\n**Status change**: %s → %s",
			markdownText(StatusLabel(it.FromStatus), 0), markdownText(StatusLabel(it.ToStatus), 0))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		out += fmt.Sprintf("\n**Type**: %s", markdownText(it.VulnClass, 0))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		out += fmt.Sprintf("\n**Assets**: %s", markdownText(a, 0))
	}
	if it.Summary != "" {
		if s := markdownText(it.Summary, maxSummaryRunes); s != "" {
			out += fmt.Sprintf("\n**Summary**: %s", s)
		}
	}
	return out
}

// feishuBatchLine renders one digest-card entry.
func feishuBatchLine(it Item, index int) string {
	line := fmt.Sprintf("**%d. %s · %s**", index, SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		line += " — " + markdownText(a, 0)
	}
	return line
}
