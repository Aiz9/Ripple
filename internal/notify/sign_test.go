package notify

import (
	"net/url"
	"testing"
	"time"
)

// Independent OpenSSL reference signatures verify algorithm correctness rather than merely
// comparing the implementation with itself.
//
//	TS=1700000000000, SECRET=SECtest123
//
// DingTalk: timestamp/newline/secret message, secret HMAC key, then base64.
//
//	-> w3RMHXzixTMdzr8OHJUmVLS4IoPJVdu+Ut1LE48MePE=
//
// Feishu: empty message, timestamp/newline/secret HMAC key, then base64.
//
//	-> Hd4xFWQU6R6ad4nzy4ETIznzlqebqH7xcTFVmONTudo=
const (
	signTestTSMillis = int64(1700000000000)
	signTestSecret   = "SECtest123"
	dingTalkExpected = "w3RMHXzixTMdzr8OHJUmVLS4IoPJVdu+Ut1LE48MePE="
	feishuExpected   = "Hd4xFWQU6R6ad4nzy4ETIznzlqebqH7xcTFVmONTudo="
)

func TestDingTalkSignMatchesReference(t *testing.T) {
	got, err := dingTalkSignedURL("https://oapi.dingtalk.com/robot/send?access_token=tok", signTestSecret, time.UnixMilli(signTestTSMillis))
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("produced address cannot be parsed: %v", err)
	}
	q := u.Query()
	if q.Get("sign") != dingTalkExpected {
		t.Errorf("signature mismatch\nwant %s\ngot %s", dingTalkExpected, q.Get("sign"))
	}
	if q.Get("timestamp") != "1700000000000" {
		t.Errorf("the timestamp should be in milliseconds and passed through as-is, got %q", q.Get("timestamp"))
	}
	// Signing must retain original access_token query parameters.
	if q.Get("access_token") != "tok" {
		t.Errorf("original query parameter lost, got %q", q.Get("access_token"))
	}
}

func TestFeishuSignMatchesReference(t *testing.T) {
	got := feishuSign("1700000000000", signTestSecret)
	if got != feishuExpected {
		t.Errorf("signature mismatch\nwant %s\ngot %s", feishuExpected, got)
	}
}

// TestSignAlgorithmsDiffer preserves opposite key/message conventions: DingTalk uses secret
// as key, Feishu the combined string. Copying one algorithm into the other fails verification;
// do not merge them during refactoring.
func TestSignAlgorithmsDiffer(t *testing.T) {
	ts := "1700000000000"
	dingURL, err := dingTalkSignedURL("https://example.com/hook", signTestSecret, time.UnixMilli(signTestTSMillis))
	if err != nil {
		t.Fatal(err)
	}
	dq, _ := url.Parse(dingURL)
	if dq.Query().Get("sign") == feishuSign(ts, signTestSecret) {
		t.Fatal("DingTalk and Feishu signatures are identical, so one of the algorithm implementations is wrong")
	}
}

func TestDingTalkNoSecretLeavesURLUntouched(t *testing.T) {
	// Unsigned bots must not gain timestamp/sign parameters.
	const hook = "https://oapi.dingtalk.com/robot/send?access_token=tok"
	got, err := dingTalkSignedURL(hook, "", time.UnixMilli(signTestTSMillis))
	if err != nil {
		t.Fatal(err)
	}
	if got != hook {
		t.Fatalf("without a secret the address must not change, got %q", got)
	}
}

func TestValidateHTTPURL(t *testing.T) {
	ok := []string{"https://example.com/hook", "http://10.0.0.1:8080/x?y=1"}
	for _, s := range ok {
		if err := validateHTTPURL(s); err != nil {
			t.Errorf("%q should be accepted: %v", s, err)
		}
	}
	// Reject file:// and other protocols outside expected http.Client handling.
	bad := []string{"", "file:///etc/passwd", "ftp://example.com", "https://", "gopher://x"}
	for _, s := range bad {
		if err := validateHTTPURL(s); err == nil {
			t.Errorf("%q should be rejected", s)
		}
	}
}
