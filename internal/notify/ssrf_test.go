package notify

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Two related hardening invariants:
// 1. Destinations must not turn the server into an SSRF relay to metadata/sensitive local services.
// 2. Destination-validation errors must not disclose embedded credentials.
//
// Most tests use loopback httptest receivers, so TestMain enables AllowLocalTargetsEnv,
// while each SSRF case explicitly clears it to assert default-deny behavior.
// Keep intentional test allowances separate from production defaults.

func TestMain(m *testing.M) {
	// Ordinary tests can reach local fake receivers; SSRF cases temporarily clear the override.
	_ = os.Setenv(AllowLocalTargetsEnv, "1")
	os.Exit(m.Run())
}

// TestDialGuardRejectsLoopbackByDefault checks the core SSRF invariant:
// default loopback delivery must fail at connection establishment.
func TestDialGuardRejectsLoopbackByDefault(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_, _ = io.WriteString(w, `{"errcode":0}`)
	}))
	defer srv.Close()

	t.Setenv(AllowLocalTargetsEnv, "") // Disable override to test defaults.
	_, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": srv.URL + "/robot/send"}, Message{Items: []Item{{Severity: "high"}}})
	if err == nil {
		t.Fatal("delivery to loopback addresses must not be allowed by default")
	}
	if hit {
		t.Fatal("the request already reached a local service\u2014\u2014the guard did not take effect")
	}
	// Explain the override for legitimate local SMTP relays.
	if !strings.Contains(err.Error(), AllowLocalTargetsEnv) {
		t.Errorf("the denial should explain how to allow it explicitly: %v", err)
	}
}

// TestDialGuardAllowsLoopbackWhenOptedIn ensures explicit opt-in permits legitimate local
// postfix/internal relays instead of blanket rejection.
func TestDialGuardAllowsLoopbackWhenOptedIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()

	t.Setenv(AllowLocalTargetsEnv, "1")
	if _, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": srv.URL + "/robot/send"}, Message{Items: []Item{{Severity: "high"}}}); err != nil {
		t.Fatalf("after explicitly allowing it, delivery should work: %v", err)
	}
}

func TestIsBlockedDialIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1",
		"169.254.169.254", // Cloud metadata: a primary reason for this guard.
		"169.254.1.1", "fe80::1",
		"0.0.0.0", "::",
		"224.0.0.1", "ff02::1",
		"::ffff:127.0.0.1", // Unmap IPv4-mapped addresses before checking to prevent bypass.
		"",
	}
	for _, s := range blocked {
		if !isBlockedDialIP(net.ParseIP(s)) {
			t.Errorf("%s should be rejected", s)
		}
	}
	// Deliberately allow RFC1918 for internal Mattermost/SMTP relays.
	// Lock this tradeoff into tests so later broad private-IP blocking requires an explicit
	// decision instead of silently breaking deployments.
	allowed := []string{"10.0.0.5", "172.16.3.4", "192.168.1.10", "8.8.8.8", "2606:4700::1111"}
	for _, s := range allowed {
		if isBlockedDialIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed (private networks are common legitimate delivery targets)", s)
		}
	}
}

// TestValidateHTTPURLRejectsLiteralPrivateTargets provides save-time feedback:
// reject sensitive literal IPs before the first delivery attempt.
func TestValidateHTTPURLRejectsLiteralPrivateTargets(t *testing.T) {
	t.Setenv(AllowLocalTargetsEnv, "")
	for _, raw := range []string{
		"http://127.0.0.1:8080/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]:8080/hook",
	} {
		if err := validateHTTPURL(raw); err == nil {
			t.Errorf("%s should be rejected at config time", raw)
		}
	}
	// Public and ordinary private addresses remain allowed; private addresses are not blocked at dial.
	for _, raw := range []string{"https://oapi.dingtalk.com/robot/send", "http://10.0.0.9/hook"} {
		if err := validateHTTPURL(raw); err != nil {
			t.Errorf("%s should pass validation: %v", raw, err)
		}
	}
}

// TestValidateHTTPURLErrorNeverLeaksCredentials covers the previously missed parse-failure path.
//
// url.Parse errors include the original URL. Redacting only http.Client.Do errors left this
// branch vulnerable; earlier permanent-error tests used parseable file/gopher/ftp schemes,
// reaching scheme validation rather than parse failure, so passing tests gave false confidence.
// Explicitly exercise malformed parsing input.
func TestValidateHTTPURLErrorNeverLeaksCredentials(t *testing.T) {
	cases := []string{
		"http://127.0.0.1/%zz?access_token=" + leakProbeToken,         // Invalid percent escape.
		"https://a.example.com:port/x?access_token=" + leakProbeToken, // Nonnumeric port.
		"http://[::1?access_token=" + leakProbeToken,                  // Unmatched brackets.
	}
	for _, raw := range cases {
		// First assert url.Parse actually fails, preventing fixtures silently exercising a different
		// branch and reproducing that false assurance.
		if _, err := url.Parse(raw); err == nil {
			t.Errorf("%q should have failed to parse, otherwise this case does not cover the target branch", raw)
			continue
		}
		err := validateHTTPURL(raw)
		if err == nil {
			t.Errorf("%q should fail validation", raw)
			continue
		}
		assertNoSecret(t, err.Error(), leakProbeToken)
	}
	// Adapter wrapping must not reintroduce the address.
	t.Setenv(AllowLocalTargetsEnv, "")
	err := (dingTalkChannel{}).Validate(map[string]any{"webhook": cases[0]})
	if err == nil {
		t.Fatal("an invalid address should fail validation")
	}
	assertNoSecret(t, err.Error(), leakProbeToken)
}

// TestEmailDialGuardRejectsLoopbackByDefault checks SMTP dial enforcement.
//
// Bare net.Dialer previously left SMTP as an SSRF gap to metadata/loopback. smtp.NewClient
// handshake errors echoed server replies through last_error/history, recreating the partial
// read primitive closed in other adapters; refusal/timeout timing also permitted port probes.
// Apply the same final connection guard.
//
// TestMain enables local targets for fake receivers, so this case must clear the override;
// otherwise it would pass with or without a guard, as happened when the gap was missed.
// Verify production defaults explicitly.
func TestEmailDialGuardRejectsLoopbackByDefault(t *testing.T) {
	f := newFakeSMTP(t)
	cfg := emailCfg(t, f, nil)

	t.Setenv(AllowLocalTargetsEnv, "") // Disable override to test defaults.
	_, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil {
		t.Fatal("email delivery to loopback addresses must not be allowed by default")
	}
	// Control must reject before connection/EHLO.
	if f.sawCommand("EHLO") || f.sawCommand("HELO") {
		t.Fatal("SMTP session already established\u2014\u2014the guard did not take effect")
	}
	// Explain how legitimate local postfix users can opt in.
	if !strings.Contains(err.Error(), AllowLocalTargetsEnv) {
		t.Errorf("the denial should explain how to allow it explicitly: %v", err)
	}
}

// TestEmailDialGuardAllowsLoopbackWhenOptedIn is the paired positive case: explicit opt-in
// permits common local/internal SMTP deployments.
func TestEmailDialGuardAllowsLoopbackWhenOptedIn(t *testing.T) {
	f := newFakeSMTP(t)
	cfg := emailCfg(t, f, nil)

	t.Setenv(AllowLocalTargetsEnv, "1")
	if _, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg()); err != nil {
		t.Fatalf("after explicitly allowing it, local SMTP delivery should work: %v", err)
	}
	if !f.sawCommand("EHLO") {
		t.Fatal("no EHLO\u2014\u2014the session was never really established")
	}
}
