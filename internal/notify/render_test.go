package notify

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateBytesKeepsValidUTF8(t *testing.T) {
	// Core invariant: byte-limited WeCom messages must not split three-byte CJK runes,
	// producing invalid UTF-8 and platform rejection.
	// Mixed ASCII/CJK lengths exercise every cut position.
	inputs := []string{
		"\u4e2d\u6587\u6d4b\u8bd5\u5185\u5bb9",
		"\u6df7\u5408 mixed \u5185\u5bb9 content",
		"a\u4e2db\u6587c\u6d4bd\u8bd5e",
		"🔴🟠🟡🔵", // Four-byte emoji make incorrect slicing more visible.
		strings.Repeat("\u6f0f\u6d1e", 100),
	}
	for _, in := range inputs {
		for max := 1; max <= len(in)+2; max++ {
			got := TruncateBytes(in, max)
			if !utf8.ValidString(got) {
				t.Fatalf("input %q max=%d: produced invalid UTF-8 %q", in, max, got)
			}
			if len(got) > max {
				t.Fatalf("input %q max=%d: result %d bytes exceeds the limit", in, max, len(got))
			}
			// Preserve content when not truncated.
			if len(in) <= max && got != in {
				t.Fatalf("input %q max=%d: changed content although under the limit -> %q", in, max, got)
			}
		}
	}
}

func TestTruncateBytesZeroMeansUnlimited(t *testing.T) {
	long := strings.Repeat("x", 10000)
	if got := TruncateBytes(long, 0); got != long {
		t.Fatal("max=0 should mean unlimited")
	}
	if got := TruncateBytes(long, -5); got != long {
		t.Fatal("max<0 should mean unlimited")
	}
}

func TestTruncateBytesEllipsisBudget(t *testing.T) {
	// Limits shorter than ellipsis must not overflow by appending it.
	got := TruncateBytes("abcdefgh", 1)
	if len(got) > 1 {
		t.Fatalf("max=1 gives %q with length %d over the limit", got, len(got))
	}
	// Ordinary truncated output includes ellipsis.
	if got := TruncateBytes("abcdefgh", 5); !strings.HasSuffix(got, ellipsis) {
		t.Fatalf("expected an ellipsis, got %q", got)
	}
}

func TestTruncateRunesCountsCharactersNotBytes(t *testing.T) {
	// Preserve character versus byte truncation for Telegram; bytes would retain only one third
	// of comparable CJK text.
	s := "\u4e00\u4e8c\u4e09\u56db\u4e94\u516d\u4e03\u516b\u4e5d\u5341"
	got := TruncateRunes(s, 5)
	if n := utf8.RuneCountInString(got); n != 5 {
		t.Fatalf("want 5 characters, got %d chars (%q)", n, got)
	}
	// The same text with byte limits must be substantially shorter.
	if utf8.RuneCountInString(TruncateBytes(s, 5)) >= 5 {
		t.Fatal("byte-based limits must not produce the same character count as character-based ones")
	}
}

func TestOneLineCollapsesWhitespace(t *testing.T) {
	got := OneLine("\u7b2c\u4e00\u884c\n\n\u7b2c\u4e8c\u884c\t\u5e26\u5236\u8868   \u591a\u7a7a\u683c", 0)
	if strings.ContainsAny(got, "\n\t") {
		t.Fatalf("should collapse all whitespace, got %q", got)
	}
	if strings.Contains(got, "  ") {
		t.Fatalf("must not keep consecutive spaces, got %q", got)
	}
	// Truncated output remains valid/readable.
	got = OneLine("\u4e00\u4e8c\u4e09\u56db\u4e94\u516d\u4e03\u516b\u4e5d\u5341", 4)
	if n := utf8.RuneCountInString(got); n != 4 {
		t.Fatalf("want 4 characters, got %d (%q)", n, got)
	}
}

func TestTruncateHTMLNeverCutsTagInHalf(t *testing.T) {
	// Partial HTML such as <a href="htt causes platform rejection.
	s := "<b>\u6807\u9898</b>\u6b63\u6587\u6b63\u6587\u6b63\u6587<a href=\"https://example.com/very/long/path\">\u67e5\u770b\u8be6\u60c5</a>"
	for max := 1; max <= utf8.RuneCountInString(s)+2; max++ {
		got := TruncateHTML(s, max)
		if n := utf8.RuneCountInString(got); max > 0 && n > max {
			t.Fatalf("max=%d: result %d characters over the limit", max, n)
		}
		// No trailing unclosed < fragment.
		if lt := strings.LastIndex(got, "<"); lt >= 0 && !strings.Contains(got[lt:], ">") {
			t.Fatalf("max=%d: trailing tag was cut -> %q", max, got)
		}
	}
}

func TestAssetLineOmitsExcess(t *testing.T) {
	if got := assetLine(nil, 3); got != "" {
		t.Fatalf("no assets should return an empty string, got %q", got)
	}
	if got := assetLine([]string{"a", "b"}, 3); got != "a, b" {
		t.Fatalf("under the limit everything should be listed, got %q", got)
	}
	// Annotate total assets on overflow so readers know what is omitted.
	got := assetLine([]string{"a", "b", "c", "d", "e"}, 2)
	if !strings.Contains(got, "5 total") {
		t.Fatalf("should note the total 5, got %q", got)
	}
}

func TestSeverityAndStatusLabels(t *testing.T) {
	if AtLeast("", "low") {
		t.Fatal("an empty level has ordinal 0, so any threshold should block it")
	}
	if !AtLeast("critical", "") {
		t.Fatal("an empty threshold should allow")
	}
	if got := StatusLabel("fixed"); got != "Fixed" {
		t.Fatalf("unknown status mapping, got %q", got)
	}
	// Echo unknown statuses without invented labels.
	if got := StatusLabel("weird_status"); got != "weird_status" {
		t.Fatalf("an unknown status should be echoed as-is, got %q", got)
	}
}

// TestTruncateHTMLNeverCutsEntity covers entity boundaries as well as tags.
// Avoid partial HTML entities.
//
// Cutting &amp; into &amp can reject the whole message in strict entity parsers,
// an excessive cost for normal oversized digest input.
func TestTruncateHTMLNeverCutsEntity(t *testing.T) {
	s := "aaaa&amp;bbbb&lt;cccc&quot;dddd"
	for max := 1; max <= utf8.RuneCountInString(s)+2; max++ {
		got := TruncateHTML(s, max)
		// No trailing ampersand fragment without its semicolon.
		if amp := strings.LastIndex(got, "&"); amp >= 0 && !strings.Contains(got[amp:], ";") {
			t.Fatalf("max=%d: entity fragment left at the end %q", max, got[amp:])
		}
		if strings.Contains(got, "&amp\x00") {
			t.Fatalf("max=%d: malformed entity present", max)
		}
	}
}
