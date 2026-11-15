package notify

import (
	"fmt"
	"strings"
)

// Shared Markdown rendering for DingTalk and WeCom.
// Feishu renders card JSON; Telegram/email render HTML in their own adapters.

// maxAssetsShown bounds listed assets; dozens per finding would overflow messages without
// adding useful IM context beyond the first few domains.
const maxAssetsShown = 3

// maxSummaryRunes keeps alerts as pointers to details rather than full reports;
// complete content remains on the platform.
const maxSummaryRunes = 120

// markdownReservedBytes budgets header counts/severity/overflow notes and footer links.
// Deduct before packing so truncation cannot remove batch identity or remaining counts,
// leaving readers unable to tell what is missing.
const markdownReservedBytes = 320

// markdownEscape escapes structural Markdown characters.
//
// Titles/summaries/classes/assets are untrusted model/target output, including target-controlled
// URL queries. Unescaped titles could inject external links or tracking images.
// For example a title containing a newline and a verification-account link could render
//
// as: Login SQL injection, followed by [Urgent: verify account](http://attacker.tld).
//
// Security engineers would see a clickable attacker link in DingTalk/Feishu;
// ![](http://attacker.tld/beacon) could disclose reader IPs and message views.
// Even benign injected bold/quotes can push important findings below a collapsed region.
// Preserve text without allowing it to change message structure.
//
// Escape headings/links/emphasis/lists/quotes/strikethrough and process backslash first,
// otherwise later inserted escape backslashes are escaped twice.
func markdownEscape(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		"`", "\\`",
		"*", `\*`,
		"_", `\_`,
		"[", `\[`,
		"]", `\]`,
		"(", `\(`,
		")", `\)`,
		"!", `\!`,
		"#", `\#`,
		">", `\>`,
		"|", `\|`,
		"~", `\~`,
	)
	return replacer.Replace(s)
}

// markdownText folds untrusted text to one line and escapes it.
// Newlines can forge list/quote structure independently of reserved-character escaping,
// so both operations are needed.
func markdownText(s string, maxRunes int) string {
	return markdownEscape(OneLine(s, maxRunes))
}

// markdownTitle returns raw, unescaped title content.
//
// Shared by Markdown, Telegram HTML, Feishu plain_text, Webhook JSON, and email subjects;
// each output context requires different escaping. Markdown escapes leak visible backslashes
// into HTML and pollute JSON data, so output-specific renderers must own escaping.
// See writeItem/feishuItemLines/telegramEscape.
// A prior shared Markdown escape introduced visible backslashes in Telegram titles,
// such as \(1\), instead of plain parentheses.
func markdownTitle(m Message) string {
	if m.Batch {
		return fmt.Sprintf("Finding digest · %d total", len(m.Items))
	}
	if len(m.Items) == 0 {
		return "Finding notification"
	}
	it := m.Items[0]
	return fmt.Sprintf("[%s] %s", SeverityLabel(it.Severity), OneLine(it.Title(), 0))
}

// markdownBody returns rendered body and number of actually included items.
//
// Only the first kept items may be marked delivered; omitted items stay queued for the next
// batch instead of silently disappearing behind a successful delivery status.
// Rendering then truncating a full batch loses tail items while history incorrectly says
// all were delivered.
//
// maxBytes<=0 disables the limit.
func markdownBody(m Message, maxBytes int) (string, int) {
	if !m.Batch {
		if len(m.Items) == 0 {
			return "", 0
		}
		var b strings.Builder
		writeItem(&b, m.Items[0], "", true)
		// Still send an oversized single item with final truncation: partial finding information
		// is preferable to no alert.
		return TruncateBytes(b.String(), maxBytes), 1
	}

	footer := ""
	if m.HomeURL != "" {
		footer = fmt.Sprintf("\n[View all in ARTEX](%s)\n", m.HomeURL)
	}
	kept := packItemCount(m.Items, maxBytes, markdownReservedBytes, footer, byteSize, func(it Item, idx int) string {
		var b strings.Builder
		writeItem(&b, it, fmt.Sprintf("%d. ", idx+1), false)
		return b.String()
	})

	items := m.Items[:kept]
	var b strings.Builder
	b.WriteString(markdownBatchIntro(m, items, len(m.Items)))
	for i, it := range items {
		writeItem(&b, it, fmt.Sprintf("%d. ", i+1), false)
	}
	b.WriteString(footer)
	return TruncateBytes(b.String(), maxBytes), kept
}

// markdownBatchIntro includes digest window/count/severity distribution.
// Readers can assess urgency without opening the platform.
//
// items are actually packed; total is the full intended batch. Explicitly report the remainder
// for subsequent messages so readers cannot mistake the visible count for the whole batch.
// Otherwise omitted items become invisible to the reader.
func markdownBatchIntro(m Message, items []Item, total int) string {
	var b strings.Builder
	if m.WindowMinutes > 0 {
		fmt.Fprintf(&b, "**%[2]d new findings in the last %[1]d minutes**", m.WindowMinutes, total)
	} else {
		fmt.Fprintf(&b, "**%d new findings**", total)
	}
	if extra := total - len(items); extra > 0 {
		fmt.Fprintf(&b, "(Showing the first %d; the remaining %d continue in the next message)", len(items), extra)
	}
	// Count severity only among included items, matching the visible entries.
	// Displayed critical counts must agree with the actual message.
	counts := map[string]int{}
	for _, it := range items {
		counts[it.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", SeverityLabel(sev), n))
		}
	}
	if len(parts) > 0 {
		b.WriteString("\n" + strings.Join(parts, " · "))
	}
	b.WriteString("\n\n")
	return b.String()
}

// writeItem renders one finding.
//
// prefix is the digest index; single=true includes summary/link, while digest uses one concise
// line instead of turning 50 findings into a full-length document.
//
// External title/class/assets/summary all pass markdownText (single-line plus escaping).
// The administrator-controlled public_base_url link is intentionally clickable and
// rendered without treating it as untrusted body text.
func writeItem(b *strings.Builder, it Item, prefix string, single bool) {
	line := fmt.Sprintf("%s**%s · %s**", prefix, SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if !single {
		// Digest mode: one line, compressed assets and summary.
		var extras []string
		if a := assetLine(it.Assets, maxAssetsShown); a != "" {
			extras = append(extras, markdownText(a, 0))
		}
		if it.Summary != "" {
			extras = append(extras, markdownText(it.Summary, 60))
		}
		if len(extras) > 0 {
			line += " — " + strings.Join(extras, " · ")
		}
		b.WriteString(line + "\n")
		return
	}
	b.WriteString(line + "\n")
	if it.IsStatusChange() {
		fmt.Fprintf(b, "**Status change**: %s → %s\n",
			markdownText(StatusLabel(it.FromStatus), 0), markdownText(StatusLabel(it.ToStatus), 0))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		fmt.Fprintf(b, "**Type**: %s\n", markdownText(it.VulnClass, 0))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		fmt.Fprintf(b, "**Assets**: %s\n", markdownText(a, 0))
	}
	if it.Summary != "" {
		if s := markdownText(it.Summary, maxSummaryRunes); s != "" {
			fmt.Fprintf(b, "**Summary**: %s\n", s)
		}
	}
	if it.DetailURL != "" {
		fmt.Fprintf(b, "[View details](%s)\n", it.DetailURL)
	}
}
