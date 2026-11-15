package notify

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// emailDialTimeout/emailSessionTimeout bound connection and whole SMTP session respectively.
// net/smtp has no built-in timeouts; a stuck server otherwise hangs delivery forever,
// and the serial single-goroutine dispatcher would stall the entire notification system.
// Both bounds are required.
const (
	emailDialTimeout    = 10 * time.Second
	emailSessionTimeout = 45 * time.Second
)

// emailChannel implements SMTP delivery.
type emailChannel struct{}

func (emailChannel) Kind() string { return KindEmail }

// SMTP has no platform cap, but use a generous default to avoid spam.
func (emailChannel) DefaultRatePerMin() int { return 60 }

// Mask only password; SMTP host/account/recipients remain readable for editing.
func (emailChannel) SecretKeys() []string { return []string{"password"} }

// host/port choose the credential recipient; tls chooses encryption. Any change requires an
// explicit password choice, including intentionally disabling TLS.
func (emailChannel) DestinationKeys() []string { return []string{"host", "port", "tls"} }

func (emailChannel) Validate(cfg map[string]any) error {
	if cfgString(cfg, "host") == "" {
		return errors.New("Missing SMTP server address")
	}
	port := cfgInt(cfg, "port")
	if port <= 0 || port > 65535 {
		return errors.New("Invalid SMTP port (must be 1–65535)")
	}
	if cfgString(cfg, "from") == "" {
		return errors.New("Missing sender address")
	}
	if len(cfgStrings(cfg, "to")) == 0 {
		return errors.New("At least one recipient is required")
	}
	return nil
}

func (c emailChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	host := cfgString(cfg, "host")
	port := cfgInt(cfg, "port")
	from := cfgString(cfg, "from")
	to := cfgStrings(cfg, "to")
	username := cfgString(cfg, "username")
	password := cfgString(cfg, "password")
	implicitTLS := cfgBool(cfg, "tls")

	msg, err := buildEmailMessage(from, to, m)
	if err != nil {
		return 0, Permanent(err)
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := emailDial(ctx, addr, host, implicitTLS)
	if err != nil {
		return 0, err
	}
	defer client.Close()

	// Upgrade with STARTTLS when supported; never send credentials over plaintext (see auth below).
	if !implicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				return 0, fmt.Errorf("STARTTLS failed: %w", err)
			}
		}
	}
	if username != "" {
		if err := client.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
			// smtp.PlainAuth correctly refuses unencrypted credentials except localhost.
			// Do not bypass this security behavior; explain it clearly instead of exposing only
			// an unhelpful unencrypted connection error.
			if strings.Contains(err.Error(), "unencrypted connection") {
				return 0, Permanent(fmt.Errorf("Refusing to send credentials over an unencrypted connection. Enable TLS or use port 465 (implicit TLS) (%w)", err))
			}
			return 0, Permanent(fmt.Errorf("SMTP authentication failed: %w", err))
		}
	}
	if err := client.Mail(from); err != nil {
		return 0, smtpStageError(fmt.Sprintf("Sender %s rejected", from), err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return 0, smtpStageError(fmt.Sprintf("Recipient %s rejected", rcpt), err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return 0, fmt.Errorf("SMTP DATA failed: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return 0, fmt.Errorf("Failed to write email body: %w", err)
	}
	if err := w.Close(); err != nil {
		return 0, fmt.Errorf("Failed to submit email: %w", err)
	}
	// Ignore Quit failure after the server has accepted the message.
	_ = client.Quit()
	// Email sends the full HTML body without truncation; all batch items count as delivered.
	return len(m.Items), nil
}

// emailDial establishes SMTP transport.
//
// implicitTLS=true covers immediate TLS on 465; false connects plaintext on 25/587 then STARTTLS.
// Do not mix them: plaintext greeting to 465 gets disconnected.
//
// Set session deadline at dial time because net/smtp hides the underlying connection in
// unexported fields; once passed in, only the preconfigured deadline can prevent hanging.
// This also covers handshake stalls.
// Reuse blockInternalDial in Control, matching HTTP adapters and closing SMTP's SSRF gap.
// Without it, 169.254.169.254/127.0.0.1 could be contacted; smtp.NewClient errors embed server
// replies, exposed through last_error/history as a partial read primitive.
// Connection refusal/timeout timing also permits port probing.
// Dial-time enforcement covers DNS rebinding too.
func emailDial(ctx context.Context, addr, host string, implicitTLS bool) (*smtp.Client, error) {
	d := &net.Dialer{Timeout: emailDialTimeout, Control: blockInternalDial}
	var conn net.Conn
	var err error
	if implicitTLS {
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to SMTP server: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(emailSessionTimeout))
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMTP handshake failed: %w", err)
	}
	return client, nil
}

// smtpStageError classifies retryability using SMTP reply codes.
//
// Distinguish reply classes:
//   - 4xx (450 greylisting, 451 local error, 452 storage shortage) are temporary and
//     should retry; greylisting commonly affects the initial attempt.
//   - 5xx (550 no user, 553 bad address) are permanent; retries cannot help.
//
// Calling every SMTP error permanent would fail all greylisted deliveries immediately,
// defeating retries where they are most useful.
// Parse the first three digits; unknown codes remain retryable rather than declaring a
// potentially transient fault permanent.
func smtpStageError(what string, err error) error {
	code := smtpReplyCode(err.Error())
	if code >= 500 && code < 600 {
		return Permanent(fmt.Errorf("%s: %w", what, err))
	}
	return fmt.Errorf("%s: %w", what, err)
}

// smtpReplyCode extracts a leading three-digit code or returns 0.
// net/smtp exposes no code field; parse text such as 450 4.7.1 ... .
func smtpReplyCode(text string) int {
	if len(text) < 3 {
		return 0
	}
	n, err := strconv.Atoi(text[:3])
	if err != nil {
		return 0
	}
	return n
}

// buildEmailMessage creates a complete RFC 5322 message.
//
// Base64 prevents HTML's long lines from exceeding SMTP's 1000-byte line limit and avoids
// lines beginning with a dot, removing dot-stuffing complications.
// Especially useful for long digest HTML.
func buildEmailMessage(from string, to []string, m Message) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	// Encode non-ASCII subjects per RFC 2047 to avoid client mojibake.
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", htmlTitle(m)))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	// No email length hard cap; preserve the whole body.
	b.WriteString("\r\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(htmlBody(m, 0)))
	// Wrap base64 at 76 characters per RFC 2045.
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded + "\r\n")
	return b.String(), nil
}
