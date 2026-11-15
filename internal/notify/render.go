package notify

import (
	"strings"
	"unicode/utf8"
)

const ellipsis = "…"

// TruncateBytes returns valid UTF-8 within max bytes, never cutting a rune.
//
// WeCom enforces 4096 bytes, not characters. Three-byte CJK text makes arbitrary slicing
// produce half-characters and invalid UTF-8, resulting in rejected or garbled messages.
// Back up from the byte budget to the nearest rune start, using utf8.RuneStart to recognize
// continuation bytes (0b10xxxxxx).
//
// max<=0 is unlimited; append ellipsis unless it cannot fit.
func TruncateBytes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	budget := max - len(ellipsis)
	suffix := ellipsis
	if budget < 0 {
		// Tiny limits omit ellipsis rather than exceeding max.
		budget = max
		suffix = ""
	}
	cut := budget
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

// OneLine folds whitespace and truncates by character count.
// IM titles/summaries must not break tables/headings with embedded newlines.
// max<=0 is unlimited.
func OneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	return TruncateRunes(s, max)
}

// TruncateRunes caps characters rather than bytes and adds ellipsis on overflow.
// max<=0 is unlimited.
//
// Keep platform units distinct: WeCom bytes versus Telegram characters.
// Wrong units silently overtruncate CJK: a 4096-byte limit holds only about 1365 characters.
// Both truncators are needed and adapters must choose correctly.
func TruncateRunes(s string, max int) string {
	if max <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 1 {
		return string(runes[:max])
	}
	return string(runes[:max-1]) + ellipsis
}

// TruncateHTML caps characters while avoiding partial tags.
//
// Raw slicing could leave <a href="htt fragments, causing rejection or swallowing later content
// as an attribute. Truncate then back up before an unclosed trailing angle bracket.
// Do not leave incomplete opening tags.
//
// Do not balance tags: Telegram closes them automatically; correctly handling attributes,
// comments, and self-closing tags adds disproportionate complexity.
func TruncateHTML(s string, max int) string {
	if max <= 0 || len([]rune(s)) <= max {
		return s
	}
	cut := TruncateRunes(s, max)
	// If the final < has no following >, remove that fragment.
	if lt := strings.LastIndex(cut, "<"); lt >= 0 && !strings.Contains(cut[lt:], ">") {
		cut = cut[:lt]
	}
	// Also back up before cut entities, such as &amp; becoming &amp.
	// Entity-only parsers may reject the entire otherwise ordinary oversized digest,
	// unnecessarily losing a complete notification.
	if amp := strings.LastIndex(cut, "&"); amp >= 0 && !strings.Contains(cut[amp:], ";") {
		cut = cut[:amp]
	}
	return cut
}

// packItemCount counts complete entries fitting the budget for digest packing.
//
// Rendering then cutting a whole batch loses unseen tail items while history marks them
// delivered. Whole-item packing leaves overflow in the database for later batches,
// preserving findings rather than silently discarding them.
// kept is the number truly delivered in this message.
//
// maxSize<=0 is unlimited; reserve budgets headers/footers; size selects channel units
// (WeCom/DingTalk bytes, Telegram characters). Wrong units silently overtruncate CJK,
// so units must be explicit.
// render measures actual per-item text; lengths vary too much to estimate.
//
// Return at least one if items remain; an extreme first item relies on final truncation,
// avoiding permanent batch starvation.
func packItemCount(items []Item, maxSize, reserve int, footer string, size func(string) int, render func(Item, int) string) int {
	if maxSize <= 0 {
		return len(items)
	}
	budget := maxSize - reserve - size(footer)
	if budget < 0 {
		budget = 0
	}
	used := 0
	for i, it := range items {
		used += size(render(it, i))
		if used > budget && i > 0 {
			return i
		}
	}
	return len(items)
}

// byteSize/runeSize name the two units instead of opaque func(string)int closures,
// making adapter choices immediately visible.
func byteSize(s string) int { return len(s) }
func runeSize(s string) int { return utf8.RuneCountInString(s) }

// assetLine lists up to limit assets on one line and annotates omitted total.
// Dozens of finding anchors would otherwise overwhelm alerts.
func assetLine(assets []string, limit int) string {
	if len(assets) == 0 {
		return ""
	}
	if limit <= 0 || len(assets) <= limit {
		return strings.Join(assets, ", ")
	}
	return strings.Join(assets[:limit], ", ") + " (" + itoa(len(assets)) + " total)"
}

// itoa aliases strconv.Itoa for display concatenation without repeated imports.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
