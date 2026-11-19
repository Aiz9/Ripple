package traffic

import "testing"

func TestParseExchange(t *testing.T) {
	req := "POST /v1/pay?x=1 HTTP/1.1\r\nHost: api.bank.test\r\nContent-Type: application/json\r\n\r\n{\"amount\":100}"
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"
	ex, ok := parseExchange("", "", req, resp, true)
	if !ok {
		t.Fatal("parse failed")
	}
	if ex.method != "POST" || ex.host != "api.bank.test" || ex.url != "https://api.bank.test/v1/pay?x=1" {
		t.Fatalf("bad parse: %+v", ex)
	}
	if ex.escapedPath != "/v1/pay" || ex.status != 200 {
		t.Fatalf("bad path/status: %q %d", ex.escapedPath, ex.status)
	}
	if ex.reqContentType != "application/json" || ex.contentType != "application/json" {
		t.Fatalf("bad content types: %q %q", ex.reqContentType, ex.contentType)
	}
	if string(ex.reqBody) != `{"amount":100}` || string(ex.respBody) != `{"ok":true}` {
		t.Fatalf("bad bodies: %q %q", ex.reqBody, ex.respBody)
	}
	// no host anywhere -> not parseable
	if _, ok := parseExchange("", "", "GET / HTTP/1.1\r\n\r\n", resp, true); ok {
		t.Error("expected failure without host")
	}
}

func TestIngestRecords(t *testing.T) {
	tr, _ := openTraffic(t)
	req := "GET /accounts/100 HTTP/1.1\r\nHost: h.test\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":100}"
	tr.Ingest("h.test", "GET", req, resp, true)
	rows, err := tr.Search("h.test", 0, 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 ingested exchange, got %d", len(rows))
	}
}
