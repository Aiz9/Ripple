package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// allowLocalTargets controls loopback/link-local delivery; default denied.
//
// Bots/public SMTP should not target these sensitive ranges: local service admin ports and
// cloud metadata at 169.254.169.254 can expose instance credentials.
// Although administrators configure destinations, XSS/CSRF-borrowed sessions or another JWT
// holder could change addresses and read replies through doJSON's first 200 response bytes
// in last_error, exposed by history APIs.
// This creates a partial-read primitive.
//
// Legitimate local SMTP relays such as postfix on 127.0.0.1:25 still need support;
// provide an explicit override instead of universally allowing local destinations.
// ANDROIDLAB_NOTIFY_ALLOW_LOCAL=1 permits them.
//
// Export AllowLocalTargetsEnv so tests can enable their 127.0.0.1 httptest receivers,
// which otherwise would be blocked across notify/server suites.
const AllowLocalTargetsEnv = "ANDROIDLAB_NOTIFY_ALLOW_LOCAL"

func allowLocalTargets() bool {
	v := strings.TrimSpace(os.Getenv(AllowLocalTargetsEnv))
	return v == "1" || strings.EqualFold(v, "true")
}

// isBlockedDialIP identifies ranges denied by default.
//
// Block loopback, link-local (including metadata), unspecified, and multicast.
// Permit RFC1918: internal Mattermost/SMTP deployments are legitimate and common.
// Blocking all private networks would make real deployments unusable; protect sensitive
// destinations without disabling ordinary installations.
func isBlockedDialIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Unmap IPv4-mapped IPv6 such as ::ffff:127.0.0.1 before checking to prevent bypass.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// blockInternalDial is the http.Transport dialer's Control hook, checking the resolved IP
// at connection establishment.
//
// Dial time is the final enforcement point beyond save-time validation, covering
// DNS rebinding (public at validation, local at connection) and redirects, including
// same-host path changes despite cross-host redirects already being denied.
// Revalidate actual connection targets.
func blockInternalDial(_, address string, _ syscall.RawConn) error {
	if allowLocalTargets() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("Cannot resolve target address %q", host)
	}
	if isBlockedDialIP(ip) {
		return fmt.Errorf("Delivery to loopback/link-local address %s denied (set %s=1 if local delivery is required)", ip, AllowLocalTargetsEnv)
	}
	return nil
}

// notifyTransport adds only a dial guard to the default transport.
// Clone preserves pooling, HTTP/2, timeouts, proxy, and other tuning, avoiding unrelated
// behavioral changes merely to add one check.
var notifyTransport = func() *http.Transport {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{}
	}
	clone := t.Clone()
	clone.DialContext = (&net.Dialer{Timeout: 10 * time.Second, Control: blockInternalDial}).DialContext
	return clone
}()

// httpClient is shared across notification channels.
//
// Do not reuse GlobalProxy intended for penetration-target traffic: unstable tunnels should
// not couple notification reliability to target-network faults.
// Send directly with a 15-second timeout; slower destinations are effectively unhealthy.
//
// Deny cross-host redirects: fixed delivery endpoints normally do not need them, and URL-based
// DingTalk access_token/WeCom key/Telegram bot credentials would leak to the new host.
// Same-host redirects such as adding a trailing slash remain permitted.
// Preserve normal same-host behavior.
var httpClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: notifyTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("Too many redirects")
		}
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("Cross-host redirect denied (%s → %s)", via[0].URL.Host, req.URL.Host)
		}
		return nil
	},
}

// respBodyLimit bounds unexpectedly large error responses; only code and a short description
// are needed for delivery history.
const respBodyLimit = 8 << 10

// doJSON sends one request and returns bounded response bytes.
//
// nil payload sends an empty body for GET or platforms not requiring content.
// Append custom Webhook headers unchanged.
//
// Classify network/5xx/408/429 as retryable; other 4xx are permanent. Retrying 403 merely
// repeats the same configuration/permission error three times.
func doJSON(ctx context.Context, method, url string, headers map[string]string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			// Serialization faults are local configuration-type bugs, not helped by retries.
			return nil, Permanent(fmt.Errorf("Failed to build request body: %w", err))
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		// Invalid URL is a permanent input error.
		// Do not expose url.Parse errors containing full credential-bearing addresses.
		return nil, Permanent(fmt.Errorf("Invalid request URL: %s", redactRequestTarget(url)))
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// Connection refusal, DNS failure, and timeout are generally transient; retry with backoff.
		//
		// Redact outgoing errors: http.Client.Do returns *url.Error containing operation, full URL,
		// and underlying cause. Destinations contain access_token/key/hook ID/Telegram bot tokens.
		// URL paths as well as queries can contain secrets.
		// Without redaction they leak into plaintext notification_deliveries.last_error, history API
		// responses bypassing config masking, server logs, and test-send 502 frontend responses.
		// Apply redaction before every outward error path.
		return nil, fmt.Errorf("Request failed: %s", redactTransportError(err))
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, respBodyLimit))
	if readErr != nil {
		return nil, fmt.Errorf("Failed to read response: %w", readErr)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}
	// Retry 429/408; other 4xx are configuration/permission problems.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
		return nil, fmt.Errorf("Remote rate limit or timeout (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("Remote service error (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	return nil, Permanent(fmt.Errorf("Remote request rejected (HTTP %d): %s", resp.StatusCode, snippet(raw)))
}

// snippet condenses response text into one short line, preventing multiline/whitespace-heavy
// last_error values from breaking history-page layout.
func snippet(raw []byte) string {
	return OneLine(string(raw), 200)
}

// redactRequestTarget emits scheme://host/... only.
//
// Centralize deliberately coarse destination redaction: discard everything after host because
// credentials have no universally safe URL position.
//
// DingTalk: query /robot/send?access_token=xxx.
// WeCom: query /cgi-bin/webhook/send?key=xxx.
// Feishu: final path /open-apis/bot/v2/hook/<hook_id>.
// Telegram: middle path /bot<token>/sendMessage.
//
// Channel-specific partial retention risks leaks whenever one platform is missed.
// Host is enough for DNS/connectivity/certificate diagnosis; identify the bot using the
// masked suffix in channel configuration.
//
// Parse failure returns a fixed placeholder; never echo raw text.
func redactRequestTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(unresolvable address)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// redactTransportError strips addresses and keeps the underlying cause.
//
// *url.Error has Op/URL/Err and Error() includes URL; read Err directly instead.
// Structural extraction is safer than string replacement across encoded/escaped URL variants,
// which can miss cases.
func redactTransportError(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		host := ""
		if u, parseErr := url.Parse(uerr.URL); parseErr == nil {
			host = u.Host
		}
		if uerr.Err != nil {
			return fmt.Sprintf("%s %s: %s", uerr.Op, host, uerr.Err)
		}
		return fmt.Sprintf("%s %s: unknown error", uerr.Op, host)
	}
	// Non-url.Error values, including redirect-policy errors, also require redaction.
	return redactURLsInText(err.Error())
}

// redactURLsInText replaces HTTP(S) URLs with redacted targets.
//
// Fallback for errors without structural fields, such as redirects or library-specific errors.
// Recognize http/https prefixes and terminate at whitespace/quotes, which cannot occur in URLs.
func redactURLsInText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		rest := s[i:]
		if strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {
			end := len(rest)
			if j := strings.IndexAny(rest, " \t\n\"'"); j >= 0 {
				end = j
			}
			b.WriteString(redactRequestTarget(rest[:end]))
			i += end
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
