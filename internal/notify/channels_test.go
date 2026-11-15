package notify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// singleMsg includes quotes/newlines in finding title/summary, inputs most likely to break
// naive JSON template interpolation.
func singleMsg() Message {
	return Message{
		Items: []Item{{
			FindingID: 42,
			Name:      "\u767b\u5f55\u5904 \"SQL\u6ce8\u5165\" \u98ce\u9669",
			VulnClass: "SQL\u6ce8\u5165",
			Severity:  "high",
			Summary:   "\u53c2\u6570 id\n\u672a\u8fc7\u6ee4 \u5bfc\u81f4\u6ce8\u5165",
			Assets:    []string{"a.example.com", "b.example.com"},
			DetailURL: "https://artex.local/function/findings/detail?id=42",
		}},
	}
}

// batchMsg constructs a digest batch.
func batchMsg(n int) Message {
	m := Message{Batch: true, WindowMinutes: 30, HomeURL: "https://artex.local/function/findings"}
	for i := 0; i < n; i++ {
		m.Items = append(m.Items, Item{
			FindingID: int64(i + 1),
			Name:      "\u6f0f\u6d1e" + itoa(i+1),
			VulnClass: "XSS",
			Severity:  "medium",
			Summary:   "\u53cd\u5c04\u578b\u8de8\u7ad9\u811a\u672c",
			Assets:    []string{"target.example.com"},
		})
	}
	return m
}

// capturePost starts a fake receiver and exposes request body/headers to assertions.
func capturePost(t *testing.T, respBody string, assert func(t *testing.T, body map[string]any, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("request body is not valid JSON: %v\nraw: %s", err, raw)
			}
		}
		if assert != nil {
			assert(t, body, r)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDingTalkSendsActionCardWhenLinkPresent(t *testing.T) {
	srv := capturePost(t, `{"errcode":0,"errmsg":"ok"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["msgtype"] != "actionCard" {
			t.Fatalf("with a link-back it should send actionCard, got %v", body["msgtype"])
		}
		card, _ := body["actionCard"].(map[string]any)
		if card["singleURL"] != "https://artex.local/function/findings/detail?id=42" {
			t.Errorf("link-back lost: %v", card["singleURL"])
		}
	})
	if _, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestDingTalkFallsBackToMarkdownForBatch(t *testing.T) {
	srv := capturePost(t, `{"errcode":0,"errmsg":"ok"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["msgtype"] != "markdown" {
			t.Fatalf("a digest should send markdown, got %v", body["msgtype"])
		}
		md, _ := body["markdown"].(map[string]any)
		if !strings.Contains(md["text"].(string), "last 30 minutes") {
			t.Errorf("digest body lacks the time window: %v", md["text"])
		}
	})
	if _, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, batchMsg(3)); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

// TestDingTalkBusinessErrorIsPermanent checks HTTP 200 with nonzero errcode.
// Ignoring business codes mislabels failed deliveries successful across these IM platforms.
func TestDingTalkBusinessErrorIsPermanent(t *testing.T) {
	srv := capturePost(t, `{"errcode":310000,"errmsg":"keywords not in content"}`, nil)
	_, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg())
	if err == nil {
		t.Fatal("errcode other than 0 should error")
	}
	if !IsPermanent(err) {
		t.Fatalf("a keyword mismatch is a config error and should be a permanent failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "310000") {
		t.Errorf("the error should include the platform error code, got %v", err)
	}
}

func TestWeComTruncatesCJKWithinByteLimit(t *testing.T) {
	var contentLen int
	srv := capturePost(t, `{"errcode":0,"errmsg":"ok"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		md, _ := body["markdown"].(map[string]any)
		content, _ := md["content"].(string)
		contentLen = len(content)
		if !utf8.ValidString(content) {
			t.Fatal("truncated text is not valid UTF-8\u2014\u2014WeCom rejects the whole message")
		}
	})
	// Long Unicode digest must exceed 4096 bytes.
	m := batchMsg(200)
	if _, err := (weComChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, m); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if contentLen > weComMarkdownLimit {
		t.Fatalf("body %d bytes exceeds the WeCom limit %d", contentLen, weComMarkdownLimit)
	}
	if contentLen == 0 {
		t.Fatal("empty body")
	}
}

func TestWeComRateLimitIsRetryableButKeyErrorIsPermanent(t *testing.T) {
	limited := capturePost(t, `{"errcode":45009,"errmsg":"api freq out of limit"}`, nil)
	_, err := (weComChannel{}).Send(context.Background(), map[string]any{"webhook": limited.URL}, singleMsg())
	if err == nil || IsPermanent(err) {
		t.Fatalf("45009 is a rolling-window rate limit and should be retryable, got %v", err)
	}

	badKey := capturePost(t, `{"errcode":93000,"errmsg":"invalid webhook url"}`, nil)
	_, err = (weComChannel{}).Send(context.Background(), map[string]any{"webhook": badKey.URL}, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("93000 means the key is invalid; retrying cannot fix it, so it should be a permanent failure, got %v", err)
	}
}

func TestFeishuCardStructureAndSign(t *testing.T) {
	const secret = "SECtest123"
	srv := capturePost(t, `{"code":0,"msg":"success"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["msg_type"] != "interactive" {
			t.Fatalf("should send an interactive card, got %v", body["msg_type"])
		}
		card, _ := body["card"].(map[string]any)
		header, _ := card["header"].(map[string]any)
		if header["template"] != "orange" {
			t.Errorf("high severity should use the orange color, got %v", header["template"])
		}
		// Configured secrets require signature fields or Feishu rejects with 19021.
		if body["sign"] == nil || body["timestamp"] == nil {
			t.Fatalf("missing signing parameters: %v", body)
		}
		// Card must contain a finding-detail URL button.
		elements, _ := card["elements"].([]any)
		foundButton := false
		for _, e := range elements {
			em, _ := e.(map[string]any)
			if em["tag"] != "action" {
				continue
			}
			actions, _ := em["actions"].([]any)
			for _, a := range actions {
				am, _ := a.(map[string]any)
				if am["url"] == "https://artex.local/function/findings/detail?id=42" {
					foundButton = true
				}
			}
		}
		if !foundButton {
			t.Fatal("the card has no button linking to the detail page")
		}
	})
	cfg := map[string]any{"webhook": srv.URL, "secret": secret}
	if _, err := (feishuChannel{}).Send(context.Background(), cfg, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestFeishuWithoutSecretOmitsSign(t *testing.T) {
	srv := capturePost(t, `{"code":0,"msg":"success"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["sign"] != nil || body["timestamp"] != nil {
			t.Fatalf("without a secret there must be no signing parameters: %v", body)
		}
	})
	if _, err := (feishuChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestTelegramEscapesHTMLInUntrustedContent(t *testing.T) {
	var text string
	srv := capturePost(t, `{"ok":true}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		text, _ = body["text"].(string)
		if body["parse_mode"] != "HTML" {
			t.Fatalf("should use HTML parse mode, got %v", body["parse_mode"])
		}
	})
	m := Message{Items: []Item{{
		Severity: "high",
		// Titles/summaries from targets or models are untrusted.
		Name:    `<script>alert(1)</script>`,
		Summary: "a & b < c",
	}}}
	if _, err := (telegramChannel{}).Send(context.Background(),
		map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": srv.URL}, m); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if strings.Contains(text, "<script>") {
		t.Fatalf("unescaped HTML, injection possible: %q", text)
	}
	if !strings.Contains(text, "&lt;script&gt;") {
		t.Fatalf("expected escaped entities, got %q", text)
	}
	if !strings.Contains(text, "a &amp; b") {
		t.Fatalf("& not escaped, got %q", text)
	}
}

func TestTelegramErrorClassification(t *testing.T) {
	rateLimited := capturePost(t, `{"ok":false,"error_code":429,"description":"Too Many Requests"}`, nil)
	_, err := (telegramChannel{}).Send(context.Background(),
		map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": rateLimited.URL}, singleMsg())
	if err == nil || IsPermanent(err) {
		t.Fatalf("429 should be retryable, got %v", err)
	}

	forbidden := capturePost(t, `{"ok":false,"error_code":403,"description":"bot was blocked by the user"}`, nil)
	_, err = (telegramChannel{}).Send(context.Background(),
		map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": forbidden.URL}, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("403 is a config problem and should be a permanent failure, got %v", err)
	}
}

func TestWebhookDefaultTemplateProducesValidJSON(t *testing.T) {
	// Default templates must safely handle title quotes/newlines: naive string interpolation
	// creates invalid JSON, while {{json .}} encodes correctly.
	srv := capturePost(t, `{"ok":true}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["title"] != "[\U0001f7e0 High] \u767b\u5f55\u5904 \"SQL\u6ce8\u5165\" \u98ce\u9669" {
			t.Errorf("title not restored correctly: %v", body["title"])
		}
		items, _ := body["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("items count should be 1, got %d", len(items))
		}
		it, _ := items[0].(map[string]any)
		if it["summary"] != "\u53c2\u6570 id\n\u672a\u8fc7\u6ee4 \u5bfc\u81f4\u6ce8\u5165" {
			t.Errorf("summary not restored correctly: %v", it["summary"])
		}
		// Numbers must remain JSON numbers, not strings from json string tags.
		if _, ok := it["finding_id"].(float64); !ok {
			t.Errorf("finding_id should be a number, got %T", it["finding_id"])
		}
	})
	if _, err := (webhookChannel{}).Send(context.Background(), map[string]any{"url": srv.URL}, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestWebhookCustomTemplateAndHeaders(t *testing.T) {
	srv := capturePost(t, `{"ok":true}`, func(t *testing.T, body map[string]any, r *http.Request) {
		if r.Header.Get("X-Token") != "s3cret" {
			t.Errorf("custom header lost: %v", r.Header)
		}
		if body["msg"] != "3 \u6761" {
			t.Errorf("custom template rendered incorrectly: %v", body["msg"])
		}
		if body["first"] != "\u6f0f\u6d1e1" {
			t.Errorf("range extraction wrong: %v", body["first"])
		}
	})
	cfg := map[string]any{
		"url":           srv.URL,
		"headers":       map[string]any{"X-Token": "s3cret"},
		"body_template": "{\"msg\": {{json (printf \"%d \u6761\" .Count)}}, \"first\": {{json (index .Items 0).Name}}}",
	}
	if _, err := (webhookChannel{}).Send(context.Background(), cfg, batchMsg(3)); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
}

func TestWebhookRejectsNonJSONRenderResult(t *testing.T) {
	cfg := map[string]any{"url": "https://example.com/hook", "body_template": `not json at all`}
	_, err := (webhookChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("a rendered result that is not JSON should be a permanent failure (the template is wrong; retrying is useless), got %v", err)
	}
}

func TestWebhookValidateCatchesBadConfigEarly(t *testing.T) {
	bad := []map[string]any{
		{},
		{"url": "file:///etc/passwd"},
		{"url": "https://example.com", "method": "DELETE"},
		{"url": "https://example.com", "body_template": `{{.Items.`},
	}
	for i, cfg := range bad {
		if err := (webhookChannel{}).Validate(cfg); err == nil {
			t.Errorf("config set %d should be rejected: %v", i, cfg)
		}
	}
}

func TestEmailMessageIsWellFormed(t *testing.T) {
	msg, err := buildEmailMessage("artex@example.com", []string{"a@example.com", "b@example.com"}, singleMsg())
	if err != nil {
		t.Fatalf("building the email failed: %v", err)
	}
	if !strings.HasPrefix(msg, "From: artex@example.com\r\n") {
		t.Fatalf("From header wrong:\n%s", msg)
	}
	if !strings.Contains(msg, "To: a@example.com, b@example.com\r\n") {
		t.Fatalf("To header wrong:\n%s", msg)
	}
	// Non-ASCII email subjects require RFC 2047 encoding.
	if !strings.Contains(msg, "Subject: =?utf-8?") {
		t.Fatalf("subject is not RFC 2047 encoded:\n%s", msg)
	}
	if dec, err := new(mime.WordDecoder).DecodeHeader(mustExtractHeader(t, msg, "Subject")); err != nil {
		t.Fatalf("subject cannot be decoded: %v", err)
	} else if !strings.Contains(dec, "SQL\u6ce8\u5165") {
		t.Fatalf("decoded subject is wrong: %q", dec)
	}

	// Decode base64 body and verify valid HTML.
	parts := strings.SplitN(msg, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatal("message lacks the header/body separator")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(parts[1]), "\r\n", ""))
	if err != nil {
		t.Fatalf("body base64 decode failed: %v", err)
	}
	html := string(decoded)
	if !strings.HasPrefix(html, "<div") {
		t.Fatalf("body is not HTML: %.80s", html)
	}
	// Double quotes are valid in HTML text; preserve title content without unnecessary escaping.
	// This catches accidental extra quote escaping that would display literal entities instead
	// of the original title.
	if !strings.Contains(html, "\"SQL\u6ce8\u5165\"") {
		t.Fatalf("quotes in the title should be kept as-is in text positions: %.200s", html)
	}
}

// TestEmailEscapesStructuralInjection covers actual HTML/email injection boundaries.
// Target/model title and summary are untrusted: escape &, <, > in text and additionally
// quotes in attributes to prevent injected tags or href termination.
func TestEmailEscapesStructuralInjection(t *testing.T) {
	m := Message{
		Items: []Item{{
			Severity:  "high",
			Name:      `<script>alert(1)</script>`,
			Summary:   "a & b > c",
			DetailURL: `https://artex.local/x?a="onmouseover=alert(1)`,
		}},
	}
	html := htmlBody(m, 0)
	if strings.Contains(html, "<script>") {
		t.Fatalf("title not escaped, tags can be injected: %s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("expected escaped entities: %s", html)
	}
	if !strings.Contains(html, "a &amp; b &gt; c") {
		t.Fatalf("& and > not escaped: %s", html)
	}
	// Admin-configured public_base_url is relatively trusted but still needs quote escaping
	// in attributes to prevent injected event handlers.
	if strings.Contains(html, `onmouseover=alert(1)">`) {
		t.Fatalf("href attribute not escaped correctly: %s", html)
	}
	if !strings.Contains(html, "&quot;") {
		t.Fatalf("quotes in attribute positions should be escaped: %s", html)
	}
}

func mustExtractHeader(t *testing.T, msg, name string) string {
	t.Helper()
	for _, line := range strings.Split(msg, "\r\n") {
		if strings.HasPrefix(line, name+": ") {
			return strings.TrimPrefix(line, name+": ")
		}
	}
	t.Fatalf("no %s header found", name)
	return ""
}

func TestChannelValidateReportsMissingFields(t *testing.T) {
	// Validation errors must identify missing fields for users.
	cases := []struct {
		kind   string
		cfg    map[string]any
		substr string
	}{
		{KindDingTalk, map[string]any{}, "webhook URL"},
		{KindFeishu, map[string]any{}, "webhook URL"},
		{KindWeCom, map[string]any{}, "webhook URL"},
		{KindTelegram, map[string]any{}, "bot token"},
		{KindTelegram, map[string]any{"bot_token": "t"}, "chat ID"},
		{KindEmail, map[string]any{}, "SMTP"},
		{KindEmail, map[string]any{"host": "h"}, "SMTP port"},
		{KindEmail, map[string]any{"host": "h", "port": 587, "from": "f"}, "recipient"},
	}
	for _, tc := range cases {
		ch, ok := Get(tc.kind)
		if !ok {
			t.Fatalf("channel %s not registered", tc.kind)
		}
		err := ch.Validate(tc.cfg)
		if err == nil {
			t.Errorf("%s config %v should fail validation", tc.kind, tc.cfg)
			continue
		}
		if !strings.Contains(err.Error(), tc.substr) {
			t.Errorf("%s error should mention %q, got %q", tc.kind, tc.substr, err.Error())
		}
	}
}

// TestEmailSMTPErrorClassification preserves SMTP 4xx versus 5xx semantics.
// Treating greylisting 4xx as permanent would fail every message on its first attempt,
// exactly where automatic retries should help.
func TestEmailSMTPErrorClassification(t *testing.T) {
	cases := []struct {
		reply     string
		permanent bool
	}{
		{"450 4.7.1 Greylisting in action, please come back later", false},
		{"451 4.3.0 Temporary system failure", false},
		{"452 4.2.2 Mailbox full", false},
		{"550 5.1.1 User unknown", true},
		{"553 5.1.3 Bad address syntax", true},
		{"554 5.7.1 Relay access denied", true},
		// Unknown reply codes remain retryable; prefer another attempt to prematurely declaring
		// a potentially transient fault permanent.
		{"unexpected EOF", false},
		{"", false},
	}
	for _, tc := range cases {
		err := smtpStageError("\u6536\u4ef6\u4eba\u88ab\u62d2", errors.New(tc.reply))
		if got := IsPermanent(err); got != tc.permanent {
			t.Errorf("reply %q: want permanent=%v got %v", tc.reply, tc.permanent, got)
		}
		// Preserve server text for diagnostics regardless of classification.
		if tc.reply != "" && !strings.Contains(err.Error(), tc.reply) {
			t.Errorf("reply %q text was dropped: %v", tc.reply, err)
		}
	}
}

func TestRegistryCoversAllKinds(t *testing.T) {
	// All six adapters must remain registered or silently disappear from the UI.
	want := []string{KindDingTalk, KindEmail, KindFeishu, KindTelegram, KindWebhook, KindWeCom}
	got := Kinds()
	if len(got) != len(want) {
		t.Fatalf("channel count should be %d, got %d: %v", len(want), len(got), got)
	}
	for _, k := range want {
		if !ValidKind(k) {
			t.Errorf("channel %s not registered", k)
		}
		if ch, ok := Get(k); !ok || ch.Kind() != k {
			t.Errorf("channel %s has Kind() that does not match its registry key", k)
		}
	}
	if ValidKind("nope") {
		t.Error("an unregistered kind must not pass validation")
	}
}

func TestPermanentErrorUnwrap(t *testing.T) {
	base := &permanentSentinel{}
	err := Permanent(base)
	if !IsPermanent(err) {
		t.Fatal("should be recognized as a permanent failure")
	}
	if !strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("the error should pass the underlying error through: %v", err)
	}
	if Permanent(nil) != nil {
		t.Fatal("Permanent(nil) must return nil")
	}
	if IsPermanent(nil) {
		t.Fatal("nil is not a permanent failure")
	}
}

type permanentSentinel struct{}

func (*permanentSentinel) Error() string { return "sentinel" }
