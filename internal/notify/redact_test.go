package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Invariant: no channel-adapter error text may expose credentials.
//
// Earlier tests covered success/business errors but omitted the most sensitive transport
// failures (refused connection, DNS, timeout), where http.Client.Do's *url.Error includes
// a full URL bearing channel secrets.
// Such errors reach four outputs:
//
// notification_deliveries.last_error in plaintext storage.
// GET /api/notify/deliveries responses bypassing config masking.
// Server logs, often exported/retained.
// Test-send API 502 responses displayed directly in the frontend.
//
// Exercise actual failing calls for every adapter and assert the probe credential never
// appears in any outward error.

// credentialCases covers URL secret positions:
// DingTalk/WeCom query, Feishu final path, Telegram middle path.
var credentialCases = []struct {
	name   string
	ch     Channel
	cfg    map[string]any
	secret string
}{
	{
		name:   "\u9489\u9489 access_token \u5728 query",
		ch:     dingTalkChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/robot/send?access_token=" + leakProbeToken},
		secret: leakProbeToken,
	},
	{
		name:   "\u4f01\u4e1a\u5fae\u4fe1 key \u5728 query",
		ch:     weComChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/cgi-bin/webhook/send?key=" + leakProbeToken},
		secret: leakProbeToken,
	},
	{
		name:   "\u98de\u4e66 hook id \u5728\u8def\u5f84\u672b\u6bb5",
		ch:     feishuChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/open-apis/bot/v2/hook/" + leakProbeToken},
		secret: leakProbeToken,
	},
	{
		name:   "Telegram bot token \u5728\u8def\u5f84\u4e2d\u6bb5",
		ch:     telegramChannel{},
		cfg:    map[string]any{"bot_token": leakProbeToken, "chat_id": "1", "base_url": "http://127.0.0.1:1"},
		secret: leakProbeToken,
	},
	{
		name:   "\u9489\u9489\u52a0\u7b7e\u5bc6\u94a5",
		ch:     dingTalkChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/robot/send", "secret": leakProbeToken},
		secret: leakProbeToken,
	},
}

// leakProbeToken is an unmistakably synthetic credential sentinel to search in errors.
const leakProbeToken = "LEAKPROBE0123456789abcdef"

// TestChannelErrorsNeverLeakCredentials enforces the core invariant.
func TestChannelErrorsNeverLeakCredentials(t *testing.T) {
	for _, tc := range credentialCases {
		t.Run(tc.name, func(t *testing.T) {
			// 127.0.0.1:1 has no listener, forcing connection refusal.
			_, err := tc.ch.Send(context.Background(), tc.cfg, Message{
				Items: []Item{{FindingID: 1, Severity: "high", Name: "\u6cc4\u9732\u63a2\u9488"}},
			})
			if err == nil {
				t.Fatal("an unreachable address should error")
			}
			assertNoSecret(t, err.Error(), tc.secret)
		})
	}
}

// TestChannelErrorsNeverLeakCredentialsInPermanentPath covers invalid URLs/business errors,
// whose outward messages also must not expose credentials.
func TestChannelErrorsNeverLeakCredentialsInPermanentPath(t *testing.T) {
	cases := []struct {
		name string
		ch   Channel
		cfg  map[string]any
	}{
		// Malformed credential-bearing URL exercises validateHTTPURL/url.Parse.
		{"invalid DingTalk address", dingTalkChannel{}, map[string]any{"webhook": "file:///" + leakProbeToken}},
		{"invalid WeCom address", weComChannel{}, map[string]any{"webhook": "gopher://" + leakProbeToken}},
		{"invalid Feishu address", feishuChannel{}, map[string]any{"webhook": "ftp://" + leakProbeToken + "/hook"}},
		{"Telegram API invalid address", telegramChannel{}, map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": "file://" + leakProbeToken}},
		{"generic Webhook invalid address", webhookChannel{}, map[string]any{"url": "javascript:" + leakProbeToken}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.ch.Send(context.Background(), tc.cfg, Message{Items: []Item{{Severity: "high"}}})
			if err == nil {
				t.Fatal("an invalid config should error")
			}
			assertNoSecret(t, err.Error(), leakProbeToken)
		})
	}
}

func assertNoSecret(t *testing.T, text, secret string) {
	t.Helper()
	if strings.Contains(text, secret) {
		t.Fatalf("error text leaked the credential %q:\n    %s", secret, text)
	}
}

func TestRedactRequestTargetKeepsOnlySchemeAndHost(t *testing.T) {
	cases := map[string]string{
		"https://oapi.dingtalk.com/robot/send?access_token=S1":    "https://oapi.dingtalk.com/…",
		"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=S2": "https://qyapi.weixin.qq.com/…",
		"https://open.feishu.cn/open-apis/bot/v2/hook/S3":         "https://open.feishu.cn/…",
		"https://api.telegram.org/botS4/sendMessage":              "https://api.telegram.org/…",
		"http://10.0.0.5:8080/hook":                               "http://10.0.0.5:8080/…",
	}
	for in, want := range cases {
		got := redactRequestTarget(in)
		if got != want {
			t.Errorf("redactRequestTarget(%q) = %q, want %q", in, got, want)
		}
		// Redacted output must contain no original path/query fragments.
		if parts := strings.SplitN(in, "://", 2); len(parts) == 2 {
			if hostAndRest := strings.SplitN(parts[1], "/", 2); len(hostAndRest) == 2 && hostAndRest[1] != "" {
				if strings.Contains(got, hostAndRest[1]) {
					t.Errorf("redacted output still contains path/query fragments %q: %q", hostAndRest[1], got)
				}
			}
		}
	}
	// Never echo unparseable input.
	for _, bad := range []string{"", "://", "not a url", "http://"} {
		if got := redactRequestTarget(bad); strings.Contains(got, bad) && bad != "" {
			t.Errorf("unparseable input %q echoed as %q", bad, got)
		}
	}
}

// TestRedactTransportErrorStripsURL targets *url.Error returned by http.Client.Do,
// the original source of credential disclosure.
func TestRedactTransportErrorStripsURL(t *testing.T) {
	inner := errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	uerr := &url.Error{
		Op:  "Post",
		URL: "https://api.telegram.org/bot" + leakProbeToken + "/sendMessage",
		Err: inner,
	}
	got := redactTransportError(uerr)
	assertNoSecret(t, got, leakProbeToken)
	if !strings.Contains(got, "api.telegram.org") {
		t.Errorf("should keep the host for debugging, got %q", got)
	}
	if !strings.Contains(got, "connection refused") {
		t.Errorf("should keep the underlying reason for debugging, got %q", got)
	}
	// Preserve Op for POST/GET diagnostic context.
	if !strings.Contains(got, "Post") {
		t.Errorf("should keep the operation name, got %q", got)
	}
}

// TestRedactURLsInTextHandlesFallback also strips addresses from non-url.Error values,
// such as custom redirect-policy errors.
func TestRedactURLsInTextHandlesFallback(t *testing.T) {
	in := fmt.Sprintf("\u62d2\u7edd\u8de8\u4e3b\u673a\u91cd\u5b9a\u5411\uff08a.example \u2192 http://b.example/bot%s/send\uff09", leakProbeToken)
	got := redactURLsInText(in)
	assertNoSecret(t, got, leakProbeToken)
	if !strings.Contains(got, "http://b.example/…") {
		t.Errorf("should replace the address with its redacted form, got %q", got)
	}
	// Preserve text without URLs.
	if plain := "dial tcp: connection refused"; redactURLsInText(plain) != plain {
		t.Error("text without an address must not be changed")
	}
}

// TestCrossHostRedirectRefused prevents forwarding URL credentials across hosts.
// Two 127.0.0.1 httptest servers with different ports have distinct Host values,
// constituting a cross-host redirect.
func TestCrossHostRedirectRefused(t *testing.T) {
	var hit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/robot/send?access_token="+leakProbeToken, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	_, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": redirector.URL + "/robot/send?access_token=" + leakProbeToken},
		Message{Items: []Item{{Severity: "high"}}})
	if err == nil {
		t.Fatal("a cross-host redirect should be rejected")
	}
	if hit {
		t.Fatal("the redirect target was reached\u2014\u2014credentials leaked through the redirect")
	}
	assertNoSecret(t, err.Error(), leakProbeToken)
}

// TestSameHostRedirectAllowed preserves normal workflows such as trailing-slash redirects,
// avoiding overly broad blocking.
func TestSameHostRedirectAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robot/send" {
			// Same host and port.
			http.Redirect(w, r, "/robot/send/", http.StatusTemporaryRedirect)
			return
		}
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()

	if _, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": srv.URL + "/robot/send"},
		Message{Items: []Item{{Severity: "high"}}}); err != nil {
		t.Fatalf("a same-host redirect must not be rejected: %v", err)
	}
}
