package agent

import (
	"testing"

	"github.com/Autumn-27/artex/internal/devicelab"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		in, want string
		param    bool
	}{
		{"/api/v1/accounts/100345/balance", "/api/v1/accounts/{id}/balance", true},
		{"/users/550e8400-e29b-41d4-a716-446655440000", "/users/{id}", true},
		{"/orders/9f8e7d6c5b4a3f21/items", "/orders/{id}/items", true},
		{"/login", "/login", false},
		{"/", "/", false},
		{"/api/v1/health", "/api/v1/health", false}, // v1 must stay literal
	}
	for _, tt := range tests {
		got, p := normalizePath(tt.in)
		if got != tt.want || p != tt.param {
			t.Errorf("normalizePath(%q) = %q,%v; want %q,%v", tt.in, got, p, tt.want, tt.param)
		}
	}
}

func TestRequestParams(t *testing.T) {
	raw := "POST /transfer?dryRun=true HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{\"to\":\"B\",\"amount\":100}"
	ps := requestParams(raw)
	got := map[string]bool{}
	for _, p := range ps {
		got[p["location"].(string)+":"+p["name"].(string)] = true
	}
	for _, want := range []string{"query:dryRun", "body:to", "body:amount"} {
		if !got[want] {
			t.Errorf("missing param %q in %v", want, got)
		}
	}
}

func TestExchangeEndpointDedup(t *testing.T) {
	a := devicelab.Exchange{Method: "GET", Host: "api.bank.test", Path: "/accounts/100/balance"}
	b := devicelab.Exchange{Method: "GET", Host: "api.bank.test", Path: "/accounts/200/balance"}
	ma, ua, _ := exchangeEndpoint(a)
	mb, ub, _ := exchangeEndpoint(b)
	if ua != ub || ma != mb {
		t.Fatalf("expected dedup: %s %s vs %s %s", ma, ua, mb, ub)
	}
	if ua != "https://api.bank.test/accounts/{id}/balance" {
		t.Fatalf("canon url = %q", ua)
	}
}

func TestRequestHasAuth(t *testing.T) {
	with := "GET /me HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t\r\n\r\n"
	without := "GET /me HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n"
	if !requestHasAuth(with) {
		t.Error("expected auth detected")
	}
	if requestHasAuth(without) {
		t.Error("expected no auth")
	}
}
