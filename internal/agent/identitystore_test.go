package agent

import (
	"strings"
	"testing"
)

func TestApplyIdentityHeaders(t *testing.T) {
	raw := "GET /api/v1/accounts/A HTTP/1.1\r\nHost: api.bank.com\r\nAuthorization: Bearer AAA\r\nAccept: application/json\r\n\r\n{\"x\":1}"
	out := applyIdentityHeaders(raw, map[string]string{"Authorization": "Bearer BBB", "Cookie": "session=b"})
	if strings.Contains(out, "Bearer AAA") {
		t.Fatalf("old Authorization not replaced:\n%s", out)
	}
	if !strings.Contains(out, "Authorization: Bearer BBB") || !strings.Contains(out, "Cookie: session=b") {
		t.Fatalf("new identity headers missing:\n%s", out)
	}
	if !strings.HasPrefix(out, "GET /api/v1/accounts/A HTTP/1.1") {
		t.Fatalf("request line changed:\n%s", out)
	}
	if !strings.HasSuffix(out, "{\"x\":1}") {
		t.Fatalf("body lost:\n%s", out)
	}
	if !strings.Contains(out, "Accept: application/json") {
		t.Fatalf("unrelated header dropped:\n%s", out)
	}
}

func TestExtractAuthHeaders(t *testing.T) {
	raw := "POST /login HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\nX-Api-Key: k\r\nContent-Type: application/json\r\n\r\n{}"
	h := extractAuthHeaders(raw)
	if h["Cookie"] != "s=1" || h["X-Api-Key"] != "k" {
		t.Fatalf("auth headers not extracted: %+v", h)
	}
	if _, ok := h["Content-Type"]; ok {
		t.Fatalf("non-auth header extracted: %+v", h)
	}
}

func TestIdentityStoreScopedByTask(t *testing.T) {
	setIdentity(4242, Identity{Role: "user_b", Headers: map[string]string{"Authorization": "Bearer B"}})
	if _, ok := getIdentity(4242, "user_b"); !ok {
		t.Fatal("identity not stored")
	}
	if _, ok := getIdentity(9999, "user_b"); ok {
		t.Fatal("identity leaked across tasks")
	}
}
