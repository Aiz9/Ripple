package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// telegramTextLimit caps sendMessage text by characters.
const telegramTextLimit = 4096

// telegramChannel implements Telegram Bot API.
//
// Platform characteristics:
//   - Authentication lives in /bot<token>/sendMessage; no signatures.
//   - HTML mode avoids MarkdownV2's 18 reserved characters, where one missed escape rejects
//     the message; HTML text requires only &, <, > escaping.
//   - HTTP 200 may still contain business failure; inspect ok.
type telegramChannel struct{}

func (telegramChannel) Kind() string { return KindTelegram }

// Telegram allows roughly 1/sec direct and 20/min group; choose a conservative default.
func (telegramChannel) DefaultRatePerMin() int { return 20 }

// Bot token is secret; chat_id is only a recipient and cannot send without the token.
func (telegramChannel) SecretKeys() []string { return []string{"bot_token"} }

// base_url chooses where tokens go, so changing it requires explicitly supplying token intent.
func (telegramChannel) DestinationKeys() []string { return []string{"base_url"} }

func (telegramChannel) Validate(cfg map[string]any) error {
	if cfgString(cfg, "bot_token") == "" {
		return errors.New("Missing bot token")
	}
	if cfgString(cfg, "chat_id") == "" {
		return errors.New("Missing chat ID")
	}
	if base := cfgString(cfg, "base_url"); base != "" {
		if err := validateHTTPURL(base); err != nil {
			return fmt.Errorf("Invalid API URL: %w", err)
		}
	}
	return nil
}

func (c telegramChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	endpoint, err := telegramEndpoint(cfg)
	if err != nil {
		return 0, Permanent(err)
	}
	text, kept := telegramHTML(m)
	payload := map[string]any{
		"chat_id":                  cfgString(cfg, "chat_id"),
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": false,
	}
	raw, err := doJSON(ctx, "POST", endpoint, nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		OK          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("Failed to parse Telegram response: %w (%s)", err, snippet(raw))
	}
	if res.OK {
		return kept, nil
	}
	// 429 rate limits are retryable; 400 arguments, 401 token, 403 block, and 404 missing chat
	// are permanent configuration failures.
	if res.ErrorCode == 429 {
		return 0, fmt.Errorf("Telegram rate limited: %s", res.Description)
	}
	return 0, Permanent(fmt.Errorf("Telegram error %d: %s", res.ErrorCode, res.Description))
}

// telegramEndpoint uses official API when base_url is empty; otherwise a self-hosted reverse
// proxy, useful where direct API access is unavailable.
func telegramEndpoint(cfg map[string]any) (string, error) {
	base := cfgString(cfg, "base_url")
	if base == "" {
		base = "https://api.telegram.org"
	}
	base = strings.TrimSuffix(base, "/")
	token := cfgString(cfg, "bot_token")
	raw := base + "/bot" + token + "/sendMessage"
	u, err := url.Parse(raw)
	if err != nil {
		// Do not expose raw parsing errors or addr containing the bot token.
		return "", fmt.Errorf("Failed to construct API URL (base: %s)", redactRequestTarget(base))
	}
	return u.String(), nil
}

// telegramHTML returns HTML and actually packed count (Channel.Send).
func telegramHTML(m Message) (string, int) {
	var b strings.Builder
	b.WriteString("<b>" + telegramEscape(markdownTitle(m)) + "</b>\n")
	if m.Batch {
		// Pack by runeSize because Telegram limits characters.
		footer := ""
		if m.HomeURL != "" {
			footer = fmt.Sprintf("\n\n<a href=\"%s\">View all in ARTEX</a>", telegramEscapeAttr(m.HomeURL))
		}
		kept := packItemCount(m.Items, telegramTextLimit, telegramReservedRunes, footer, runeSize, func(it Item, idx int) string {
			return telegramBatchLine(it, idx+1)
		})
		items := m.Items[:kept]
		b.Reset()
		b.WriteString("<b>" + telegramEscape(telegramBatchTitle(m, items, len(m.Items))) + "</b>")
		for i, it := range items {
			b.WriteString("\n" + telegramEscape(telegramBatchLine(it, i+1)))
		}
		b.WriteString(footer)
		return TruncateHTML(b.String(), telegramTextLimit), kept
	}
	if len(m.Items) == 0 {
		return b.String(), 0
	}
	it := m.Items[0]
	if it.IsStatusChange() {
		b.WriteString(fmt.Sprintf("\n<b>Status change</b>: %s → %s",
			telegramEscape(StatusLabel(it.FromStatus)), telegramEscape(StatusLabel(it.ToStatus))))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		b.WriteString("\n<b>Type</b>: " + telegramEscape(it.VulnClass))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		b.WriteString("\n<b>Assets</b>: " + telegramEscape(a))
	}
	if s := OneLine(it.Summary, maxSummaryRunes); s != "" {
		b.WriteString("\n<b>Summary</b>: " + telegramEscape(s))
	}
	if it.DetailURL != "" {
		b.WriteString(fmt.Sprintf("\n\n<a href=\"%s\">View details</a>", telegramEscapeAttr(it.DetailURL)))
	}
	return TruncateHTML(b.String(), telegramTextLimit), 1
}

// telegramReservedRunes budgets title and possible overflow notes in character units.
const telegramReservedRunes = 160

// telegramBatchLine returns raw text; caller handles escaping.
func telegramBatchLine(it Item, idx int) string {
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		return fmt.Sprintf("%d. %s · %s — %s", idx, SeverityLabel(it.Severity), it.Title(), a)
	}
	return fmt.Sprintf("%d. %s · %s", idx, SeverityLabel(it.Severity), it.Title())
}

// telegramBatchTitle counts actual included items rather than the full batch,
// avoiding misleading readers about unseen entries.
func telegramBatchTitle(m Message, items []Item, total int) string {
	title := fmt.Sprintf("Finding digest · %d total", total)
	if extra := total - len(items); extra > 0 {
		title += fmt.Sprintf("(Showing the first %d; the remaining %d continue in the next message)", len(items), extra)
	}
	if m.WindowMinutes > 0 {
		title = fmt.Sprintf("Last %d minutes · %s", m.WindowMinutes, title)
	}
	return title
}

// telegramEscape escapes HTML text.
// Existing entities are deliberately escaped again to display original characters rather than
// allowing user-supplied HTML interpretation.
func telegramEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// telegramEscapeAttr additionally handles quotes so URL values cannot close href attributes
// and create injection points.
func telegramEscapeAttr(s string) string {
	s = telegramEscape(s)
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
