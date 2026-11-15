package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Tests for doJSON's HTTP error classification, independent of platform business errors.
//
// Adapters check DingTalk errcode/Feishu code/Telegram ok, while doJSON separately handles
// HTTP status classification. Both protections are needed: missing the HTTP layer would make
// 503 gateways permanently fail and 403 configurations retry pointlessly.
// Keep the two error layers distinct.

func replyServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDoJSONClassifiesHTTPStatus(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		permanent bool
	}{
		{"200 success is not an error", 200, false},
		{"429 rate limit is retryable", 429, false},
		{"408 request timeout is retryable", 408, false},
		{"500 server error is retryable", 500, false},
		{"502 gateway error is retryable", 502, false},
		{"503 service unavailable is retryable", 503, false},
		{"400 bad request is a permanent failure", 400, true},
		{"401 authentication failure is a permanent failure", 401, true},
		{"403 forbidden is a permanent failure", 403, true},
		{"404 missing address is a permanent failure", 404, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := replyServer(t, tc.status, `{"detail":"upstream says no"}`)
			_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
			if tc.status < 300 {
				if err != nil {
					t.Fatalf("2xx should not error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("non- 2xx should error")
			}
			if got := IsPermanent(err); got != tc.permanent {
				t.Fatalf("HTTP %d result: permanent misjudged: want %v got %v (%v)",
					tc.status, tc.permanent, got, err)
			}
			// Include status codes so users distinguish configuration errors from server failures.
			// Assert numeric status rather than localized wording; codes are language-independent
			// and stable across translations.
			if !strings.Contains(err.Error(), strconv.Itoa(tc.status)) {
				t.Errorf("the error should include the HTTP status code %d, got %v", tc.status, err)
			}
		})
	}
}

// TestDoJSONIncludesResponseSnippet preserves the destination's rejection explanation,
// so users see why delivery failed.
func TestDoJSONIncludesResponseSnippet(t *testing.T) {
	srv := replyServer(t, 400, `{"error":"invalid webhook token"}`)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("should error")
	}
	if !strings.Contains(err.Error(), "invalid webhook token") {
		t.Errorf("the error should carry the peer's explanation, got %v", err)
	}
}

// TestDoJSONSnippetIsSingleLineAndBounded keeps history/table errors compact:
// response text enters last_error and frontend tables, where multiline/long values break layout.
func TestDoJSONSnippetIsSingleLineAndBounded(t *testing.T) {
	// Response includes newlines, tabs, and 5000 characters.
	long := strings.Repeat("x", 5000)
	srv := replyServer(t, 500, "line1\nline2\r\n\tline3 "+long)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("should error")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\r\n\t") {
		t.Errorf("the error should be collapsed to one line, got %q", msg)
	}
	// Snippet max 200 characters plus fixed prefix, substantially below original size.
	if len(msg) > 400 {
		t.Errorf("error too long (%d bytes), should be cut by snippet truncation: %q", len(msg), msg)
	}
}

// TestDoJSONRejectsOversizedResponse ensures huge responses are not fully loaded into memory,
// since every delivery history row stores its own last_error.
func TestDoJSONRejectsOversizedResponse(t *testing.T) {
	huge := strings.Repeat("A", 1<<20) // 1 MiB
	srv := replyServer(t, 400, huge)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("should error")
	}
	if len(err.Error()) > 400 {
		t.Errorf("an oversized response should be read with a limit and truncated, error length %d", len(err.Error()))
	}
}
