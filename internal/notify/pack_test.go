package notify

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Verify whole-item digest packing: truncate only between items and report the number fitting,
// allowing callers to mark only actually delivered entries successful.
//
// Rendering the whole batch then cutting text previously lost tail entries while history
// incorrectly showed complete success, making missed findings invisible.

func TestMarkdownBodyPacksWholeItemsWithinByteLimit(t *testing.T) {
	// 200 Unicode findings far exceed WeCom's 4096-byte limit.
	m := batchMsg(200)
	body, kept := markdownBody(m, weComMarkdownLimit)

	if len(body) > weComMarkdownLimit {
		t.Fatalf("body %d bytes exceeds the limit %d", len(body), weComMarkdownLimit)
	}
	if !utf8.ValidString(body) {
		t.Fatal("body is not valid UTF-8")
	}
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("should fit only part of it (0 < kept < %d), got %d", len(m.Items), kept)
	}
	// Header must state included and remaining counts so readers do not mistake a partial message
	// for the full batch.
	if !strings.Contains(body, "remaining") || !strings.Contains(body, "next message") {
		t.Fatalf("the header should state how many items are not included in this message:\n%s", body[:minInt(400, len(body))])
	}
	// Include only the first kept entries.
	for i := 0; i < kept; i++ {
		if !strings.Contains(body, "\u6f0f\u6d1e"+itoa(i+1)) {
			t.Fatalf("item %d should be in this message:\n%s", i+1, body)
		}
	}
	if strings.Contains(body, "\u6f0f\u6d1e"+itoa(kept+1)) {
		t.Fatalf("item %d must not appear (it belongs to the next batch)", kept+1)
	}
}

func TestMarkdownBodyKeepsEverythingWhenUnderLimit(t *testing.T) {
	m := batchMsg(3)
	body, kept := markdownBody(m, 0) // 0 means unlimited.
	if kept != len(m.Items) {
		t.Fatalf("without a length limit everything should be kept, got kept=%d", kept)
	}
	if strings.Contains(body, "remaining") {
		t.Fatalf("no truncation notice should appear without truncation:\n%s", body)
	}
}

func TestMarkdownBodyAlwaysKeepsAtLeastOneItem(t *testing.T) {
	// Still include one item when the budget is tiny, leaving final truncation to the sender,
	// or an oversized first finding would stall the entire batch forever.
	m := batchMsg(5)
	_, kept := markdownBody(m, 50)
	if kept != 1 {
		t.Fatalf("should keep at least 1 item, got %d", kept)
	}
}

func TestMarkdownBodySingleReturnsOne(t *testing.T) {
	_, kept := markdownBody(singleMsg(), 4096)
	if kept != 1 {
		t.Fatalf("a single message should report 1 item delivered, got %d", kept)
	}
	// Empty messages contain no deliverable items.
	if _, k := markdownBody(Message{}, 4096); k != 0 {
		t.Fatalf("an empty message should report 0 items, got %d", k)
	}
}

func TestTelegramPackingUsesRuneBudget(t *testing.T) {
	m := batchMsg(200)
	text, kept := telegramHTML(m)
	// Telegram limits characters, not bytes; byte limits cut three-byte CJK content to one third.
	if n := utf8.RuneCountInString(text); n > telegramTextLimit {
		t.Fatalf("body %d characters exceeds the limit %d", n, telegramTextLimit)
	}
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("should fit only part of it, got %d", kept)
	}
	if !strings.Contains(text, "next message") {
		t.Fatalf("should state that some remainder is not included:\n%.300s", text)
	}
}

func TestFeishuPackingReportsKept(t *testing.T) {
	m := batchMsg(2000)
	_, kept := feishuCard(m)
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("the card should fit only part of it, got %d", kept)
	}
}

func TestWebhookAndEmailReportAllItems(t *testing.T) {
	// These two channels do not truncate bodies; count the whole batch delivered.
	m := batchMsg(7)
	if n := len(m.Items); n != 7 {
		t.Fatal("precondition does not hold")
	}
	// Verify unlimited markdownBody(0) preserves every item through renderer output.
	if _, k := markdownBody(m, 0); k != len(m.Items) {
		t.Fatalf("without a length limit everything should be used, got %d", k)
	}
}

// TestMarkdownEscapesUntrustedContent prevents external content changing message structure.
// Model summaries reflect target responses; asset names come from target URLs.
func TestMarkdownEscapesUntrustedContent(t *testing.T) {
	cases := []struct {
		name  string
		item  Item
		must  []string // Required escaped forms.
		wrong []string // Forbidden unescaped forms.
	}{
		{
			name: "\u6807\u9898\u91cc\u7684\u6362\u884c + \u5916\u94fe",
			item: Item{
				Severity: "high",
				Name:     "\u767b\u5f55\u53e3 SQL \u6ce8\u5165\n[\u7d27\u6025\uff1a\u70b9\u6b64\u9a8c\u8bc1\u8d26\u53f7](http://attacker.tld)",
			},
			// Collapse newlines to prevent forged list/quote blocks;
			// escape brackets/parentheses to prevent clickable injected links.
			must:  []string{"\\[\u7d27\u6025\uff1a\u70b9\u6b64\u9a8c\u8bc1\u8d26\u53f7\\]", `\(http://attacker.tld\)`},
			wrong: []string{"\n[\u7d27\u6025", "\n\n[\u7d27\u6025"},
		},
		{
			name: "\u6807\u9898\u91cc\u7684\u56fe\u7247\u4fe1\u6807",
			item: Item{
				Severity: "high",
				Name:     "\u6f0f\u6d1e ![](http://attacker.tld/beacon)",
			},
			must:  []string{`\!`, `\(http://attacker.tld/beacon\)`},
			wrong: []string{"![]("},
		},
		{
			name: "\u8d44\u4ea7\u540d\u91cc\u7684\u5f3a\u8c03\u4e0e\u5f15\u7528",
			item: Item{
				Severity: "high",
				Name:     "\u666e\u901a\u6807\u9898",
				Assets:   []string{"a.com/*\u6ce8\u5165*>\u5f15\u7528"},
			},
			must:  []string{"\\*\u6ce8\u5165\\*", `\>`},
			wrong: []string{"*\u6ce8\u5165*"},
		},
		{
			name: "\u6458\u8981\u91cc\u7684\u53cd\u5f15\u53f7\u4e0e\u7ad6\u7ebf",
			item: Item{
				Severity: "high",
				Name:     "\u6807\u9898",
				Summary:  "`code` | \u8868\u683c",
			},
			must:  []string{"\\`code\\`", `\|`},
			wrong: []string{"`code`"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := Message{Items: []Item{tc.item}}
			// Single-item writeItem is shared across three Markdown output paths.
			var b strings.Builder
			writeItem(&b, tc.item, "", true)
			got := b.String()
			for _, want := range tc.must {
				if !strings.Contains(got, want) {
					t.Errorf("missing escaped form %q:\n%s", want, got)
				}
			}
			for _, bad := range tc.wrong {
				if strings.Contains(got, bad) {
					t.Errorf("unescaped form present %q (usable to inject structure or external links):\n%s", bad, got)
				}
			}
			_ = m
		})
	}
}

// TestMarkdownEscapeBackslashFirst ensures backslashes are handled before added escape slashes,
// avoiding double escaping.
func TestMarkdownEscapeBackslashFirst(t *testing.T) {
	if got := markdownEscape(`a\b*c`); got != `a\\b\*c` {
		t.Fatalf("wrong escaping order, got %q", got)
	}
}

// TestTelegramTitleHasNoMarkdownEscapes protects against the prior shared-title regression:
// Markdown escaping must not leak visible backslashes into Telegram HTML titles,
// such as escaped parentheses.
func TestTelegramTitleHasNoMarkdownEscapes(t *testing.T) {
	m := Message{Items: []Item{{Severity: "high", Name: "alert(1) *\u91cd\u70b9*"}}}
	text, _ := telegramHTML(m)
	if strings.Contains(text, `\(`) || strings.Contains(text, `\*`) {
		t.Fatalf("Telegram body contains markdown backslash escapes:\n%s", text)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
