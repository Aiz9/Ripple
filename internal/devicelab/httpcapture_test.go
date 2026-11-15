package devicelab

import (
	"strings"
	"testing"
)

func TestGenerateRuntimeCaptureScript(t *testing.T) {
	s := GenerateRuntimeCaptureScript(nil)
	for _, want := range []string{"function emit(", "okhttp3.OkHttpClient", "java.net.URL", "http_request", "hooks_ready"} {
		if !strings.Contains(s, want) {
			t.Fatalf("script missing %q", want)
		}
	}
}

func TestRuntimeEndpointsFromEvents(t *testing.T) {
	events := []FridaEvent{
		{"kind": "http_request", "lib": "okhttp", "method": "POST", "url": "https://api.bank.com/v1/transfers?token=secret"},
		{"kind": "http_request", "lib": "okhttp", "method": "POST", "url": "https://api.bank.com/v1/transfers?token=other"}, // dup after query strip
		{"kind": "http_request", "lib": "urlconnection", "method": "?", "url": "https://api.bank.com/v1/accounts"},
		{"kind": "http_request", "method": "GET", "url": "file:///data/local.txt"}, // non-http, skipped
		{"kind": "ssl_bypass_applied", "hook": "x"},                                // not a request
	}
	eps := RuntimeEndpointsFromEvents(events)
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %d: %+v", len(eps), eps)
	}
	if eps[0].Path != "/v1/transfers" || eps[0].Method != "POST" {
		t.Fatalf("unexpected first endpoint: %+v", eps[0])
	}
	if strings.Contains(eps[0].URL, "secret") || strings.Contains(eps[0].URL, "other") {
		t.Fatalf("query value not stripped: %s", eps[0].URL)
	}
}
