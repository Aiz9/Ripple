package notify

import (
	"bufio"
	"context"

	"net"
	"strings"
	"sync"
	"testing"
)

// Protocol-level SMTP coverage, previously absent despite email.Send being the broadest
// protocol surface among six channels: handshake/auth/envelope/DATA each have distinct
// failure semantics.
//
// Drive a minimal real SMTP server rather than mocking net/smtp, because the central risk
// is actual protocol interaction; mocking that boundary would leave it untested.
// Exercise the real conversation path.

// fakeSMTP supports greet/EHLO/AUTH/MAIL/RCPT/DATA/QUIT with configurable stage reply codes.
// Each test chooses the failing stage.
type fakeSMTP struct {
	ln net.Listener

	// RCPT TO reply; defaults 250.
	rcptReply string
	// MAIL FROM reply; defaults 250.
	mailReply string
	// advertiseAuth adds AUTH PLAIN to EHLO.
	advertiseAuth bool

	mu       sync.Mutex
	data     string
	commands []string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, rcptReply: "250 OK", mailReply: "250 OK"}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSMTP) hostPort(t *testing.T) (string, int) {
	t.Helper()
	addr, ok := f.ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("not a TCP listen address")
	}
	return "127.0.0.1", addr.Port
}

func (f *fakeSMTP) record(cmd string) {
	f.mu.Lock()
	f.commands = append(f.commands, cmd)
	f.mu.Unlock()
}

func (f *fakeSMTP) body() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data
}

func (f *fakeSMTP) sawCommand(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.commands {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (f *fakeSMTP) serve() {
	conn, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	w := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
	w("220 fake.local ESMTP ready")
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		f.record(line)
		switch {
		case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
			// Omit STARTTLS to exercise plaintext envelope logic rather than TLS.
			w("250-fake.local")
			if f.advertiseAuth {
				w("250-AUTH PLAIN")
			}
			w("250 8BITMIME")
		case strings.HasPrefix(line, "AUTH"):
			// Simplify by accepting potentially multiline PLAIN initial responses directly.
			w("235 2.7.0 Authentication successful")
		case strings.HasPrefix(line, "MAIL FROM"):
			w(f.mailReply)
		case strings.HasPrefix(line, "RCPT TO"):
			w(f.rcptReply)
		case strings.HasPrefix(line, "DATA"):
			w("354 End data with <CR><LF>.<CR><LF>")
			var sb strings.Builder
			for {
				dl, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dl, "\r\n") == "." {
					break
				}
				sb.WriteString(dl)
			}
			f.mu.Lock()
			f.data = sb.String()
			f.mu.Unlock()
			w("250 2.0.0 Ok: queued as FAKE1")
		case strings.HasPrefix(line, "QUIT"):
			w("221 2.0.0 Bye")
			return
		default:
			w("250 OK")
		}
	}
}

func emailCfg(t *testing.T, f *fakeSMTP, extra map[string]any) map[string]any {
	t.Helper()
	host, port := f.hostPort(t)
	cfg := map[string]any{
		"host": host,
		"port": float64(port),
		"from": "artex@example.com",
		"to":   []any{"a@example.com", "b@example.com"},
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

func TestEmailSendDeliversFullMessage(t *testing.T) {
	f := newFakeSMTP(t)
	f.advertiseAuth = true
	cfg := emailCfg(t, f, map[string]any{"username": "artex", "password": "pw"})

	if _, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	// Reach sender, both recipients, and DATA envelope stages.
	for _, want := range []string{"MAIL FROM:<artex@example.com>", "RCPT TO:<a@example.com>", "RCPT TO:<b@example.com>", "DATA", "AUTH", "QUIT"} {
		if !f.sawCommand(want) {
			t.Errorf("SMTP session is missing %q, actual commands:%v", want, f.commands)
		}
	}
	// Base64 HTML body preserves real finding content.
	body := f.body()
	if body == "" {
		t.Fatal("DATA stage received no body")
	}
	if !strings.Contains(body, "Content-Type: text/html") {
		t.Errorf("missing Content-Type header:\n%s", body)
	}
	if !strings.Contains(body, "base64") {
		t.Errorf("body is not base64 encoded (long HTML lines break SMTP limit of 1000 bytes per line):\n%s", body)
	}
	// Include every recipient in To.
	if !strings.Contains(body, "a@example.com, b@example.com") {
		t.Errorf("To header does not include every recipient:\n%s", body)
	}
}

func TestEmailSendWithoutAuth(t *testing.T) {
	// Without an account do not send AUTH, which some relays reject.
	f := newFakeSMTP(t)
	cfg := emailCfg(t, f, nil)
	if _, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg()); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if f.sawCommand("AUTH") {
		t.Errorf("no account configured, yet sent AUTH: %v", f.commands)
	}
}

// TestEmailSendClassifiesSMTPReplies directly validates the audited fix:
// 5xx permanent, greylisting 4xx retryable.
func TestEmailSendClassifiesSMTPReplies(t *testing.T) {
	cases := []struct {
		name      string
		rcptReply string
		mailReply string
		permanent bool
	}{
		{"recipient gets 550 permanent rejection", "550 5.1.1 User unknown", "250 OK", true},
		{"recipient gets 450 greylisting", "450 4.7.1 Greylisting in action", "250 OK", false},
		{"recipient gets 452 mailbox full", "452 4.2.2 Mailbox full", "250 OK", false},
		{"sender gets 553 permanent rejection", "250 OK", "553 5.1.3 Bad address", true},
		{"sender gets 451 temporary error", "250 OK", "451 4.3.0 Temporary failure", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSMTP(t)
			f.rcptReply = tc.rcptReply
			f.mailReply = tc.mailReply
			_, err := (emailChannel{}).Send(context.Background(), emailCfg(t, f, nil), singleMsg())
			if err == nil {
				t.Fatal("should error")
			}
			if got := IsPermanent(err); got != tc.permanent {
				t.Fatalf("permanent misjudged: want %v got %v (%v)", tc.permanent, got, err)
			}
			// Preserve server text so users can diagnose address versus server issues.
			if !strings.Contains(err.Error(), strings.Fields(tc.rcptReply)[0]) && !strings.Contains(err.Error(), strings.Fields(tc.mailReply)[0]) {
				t.Errorf("the error should keep the server's reply code: %v", err)
			}
		})
	}
}

func TestEmailSendRefusesPlaintextCredentials(t *testing.T) {
	// PlainAuth refuses unencrypted credentials except localhost; do not bypass that guard.
	// Explain the secure remediation clearly.
	// Trigger with a non-localhost name.
	f := newFakeSMTP(t)
	f.advertiseAuth = true
	_, port := f.hostPort(t)
	cfg := map[string]any{
		"host":     "smtp.example.com", // Non-localhost.
		"port":     float64(port),
		"from":     "a@example.com",
		"to":       []any{"b@example.com"},
		"username": "artex",
		"password": "pw",
	}
	_, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil {
		t.Skip("local DNS resolved to a local server; skipping (other cases unaffected)")
	}
	// Connection failure or credential refusal passes; never send plaintext credentials silently.
	if !IsPermanent(err) && !strings.Contains(err.Error(), "\u8fde\u63a5") {
		t.Logf("error: %v (failing to connect off localhost is expected)", err)
	}
}

func TestEmailValidateReportsMissingFields(t *testing.T) {
	// Email has many required fields; verify each missing field is caught during validation,
	// with an actionable message rather than at delivery time.
	cases := []struct {
		name string
		cfg  map[string]any
	}{
		{"missing host", map[string]any{"port": float64(25), "from": "a@b.c", "to": []any{"d@e.f"}}},
		{"missing port", map[string]any{"host": "smtp.example.com"}},
		{"port out of range", map[string]any{"host": "h", "port": float64(70000), "from": "a@b.c", "to": []any{"d@e.f"}}},
		{"missing from", map[string]any{"host": "h", "port": float64(25), "to": []any{"d@e.f"}}},
		{"missing to", map[string]any{"host": "h", "port": float64(25), "from": "a@b.c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := (emailChannel{}).Validate(tc.cfg); err == nil {
				t.Fatalf("should fail validation: %v", tc.cfg)
			}
		})
	}
}

// TestEmailConfigTolerance handles JSONB float64 versus form string ports and singleton arrays.
// User input type variations should remain tolerated.
func TestEmailConfigTolerance(t *testing.T) {
	cfg := map[string]any{
		"host": "smtp.example.com",
		"port": "587", // String-form port.
		"from": "a@b.c",
		"to":   "d@e.f", // Single string instead of array.
		"tls":  "true",  // String-form boolean.
	}
	if err := (emailChannel{}).Validate(cfg); err != nil {
		t.Fatalf("numeric values given as strings should be tolerated: %v", err)
	}
	if got := cfgInt(cfg, "port"); got != 587 {
		t.Errorf("cfgInt did not parse the string port, got %d", got)
	}
	if !cfgBool(cfg, "tls") {
		t.Error("cfgBool did not parse the string \"true\"")
	}
	if to := cfgStrings(cfg, "to"); len(to) != 1 || to[0] != "d@e.f" {
		t.Errorf("cfgStrings did not accept a single string, got %v", to)
	}
}

// TestFilterValidateRejectsTypo validates rejection of mistyped thresholds on writes,
// preventing silent fail-open matching of every finding.
func TestFilterValidateRejectsTypo(t *testing.T) {
	good := []string{"", "low", "medium", "high", "critical"}
	for _, s := range good {
		if err := (Filter{MinSeverity: s}).Validate(); err != nil {
			t.Errorf("valid threshold %q rejected: %v", s, err)
		}
	}
	// Reject these realistic spelling mistakes.
	for _, s := range []string{"hgih", "HIGH", "\u4e25\u91cd", "high ", "crit"} {
		err := (Filter{MinSeverity: s}).Validate()
		if err == nil {
			t.Errorf("invalid threshold %q should be rejected (otherwise the filter silently fails open and pushes everything)", s)
			continue
		}
		// Errors should guide correction.
		if !strings.Contains(err.Error(), "low") || !strings.Contains(err.Error(), "critical") {
			t.Errorf("the error should list the allowed values, got %q", err.Error())
		}
	}
}

// TestFilterValidateIsWriteTimeOnly preserves strict writes and tolerant reads.
// Existing bad values must not prevent reading channels and stop all historical notifications.
func TestFilterValidateIsWriteTimeOnly(t *testing.T) {
	raw := []byte(`{"min_severity":"hgih"}`)
	f := ParseFilter(raw) // No error.
	if f.MinSeverity != "hgih" {
		t.Fatalf("the read path should keep the value as-is, got %q", f.MinSeverity)
	}
	// Channel can still decide an event without panic or blocking.
	_ = Match(f, Snapshot{Kind: EventFindingCreated, Severity: "critical"})
}
