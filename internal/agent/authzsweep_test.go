package agent

import (
	"testing"

	"github.com/Autumn-27/artex/internal/devicelab"
)

func TestIdentityOwnsRequest(t *testing.T) {
	raw := "GET /me HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer A\r\n\r\n"
	owner := Identity{Role: "a", Headers: map[string]string{"Authorization": "Bearer A"}}
	other := Identity{Role: "b", Headers: map[string]string{"Authorization": "Bearer B"}}
	if !identityOwnsRequest(raw, owner) {
		t.Error("owner should match its own request")
	}
	if identityOwnsRequest(raw, other) {
		t.Error("other identity must not match owner's request")
	}
	if identityOwnsRequest(raw, Identity{Role: "c"}) {
		t.Error("identity with no headers must not match")
	}
}

func TestOwnerExchanges(t *testing.T) {
	hist := []devicelab.Exchange{
		{Method: "GET", Host: "h", Path: "/accounts/100", Request: "GET /accounts/100 HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer A\r\n\r\n", Response: "HTTP/1.1 200 OK\r\n\r\nx"},
		{Method: "GET", Host: "h", Path: "/accounts/200", Request: "GET /accounts/200 HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer A\r\n\r\n", Response: "HTTP/1.1 200 OK\r\n\r\nx"},  // same template -> deduped
		{Method: "GET", Host: "h", Path: "/public", Request: "GET /public HTTP/1.1\r\nHost: h\r\n\r\n", Response: "HTTP/1.1 200 OK\r\n\r\nx"},                                         // no auth -> skipped
		{Method: "GET", Host: "h", Path: "/accounts/300", Request: "GET /accounts/300 HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer A\r\n\r\n", Response: "HTTP/1.1 500 ERR\r\n\r\nx"}, // not 2xx -> skipped
	}
	owners := ownerExchanges(hist)
	if len(owners) != 1 {
		t.Fatalf("expected 1 representative owner exchange, got %d", len(owners))
	}
	if m, u, _ := exchangeEndpoint(owners[0]); u != "https://h/accounts/{id}" || m != "GET" {
		t.Fatalf("unexpected representative: %s %s", m, u)
	}
}
