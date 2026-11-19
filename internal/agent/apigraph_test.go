package agent

import (
	"testing"

	"github.com/Aiz9/ripple/internal/devicelab"
)

func TestObjectName(t *testing.T) {
	cases := map[string]string{
		"/accounts/{id}":                    "accounts",
		"/accounts/{id}/beneficiaries":      "beneficiaries",
		"/accounts/{id}/beneficiaries/{id}": "beneficiaries",
		"/login":                            "login",
		"/":                                 "/",
	}
	for in, want := range cases {
		if got := objectName(in); got != want {
			t.Errorf("objectName(%q) = %q want %q", in, got, want)
		}
	}
}

func TestCollectJSONIDs(t *testing.T) {
	ids := collectJSONIDs(`{"account_id":"100345","amount":4200,"nested":{"txn_id":"T77"},"items":[{"order_id":"OD12345"}]}`)
	for _, want := range []string{"100345", "T77", "OD12345"} {
		if !ids[want] {
			t.Errorf("missing id %q in %v", want, ids)
		}
	}
	// amount (not an id key) must not be collected
	if ids["4200"] {
		t.Error("amount wrongly collected as id")
	}
}

func TestBuildAPIGraphDependency(t *testing.T) {
	resp := func(body string) string { return "HTTP/1.1 200 OK\r\n\r\n" + body }
	req := func(method, pathWithQuery, body string) string {
		r := method + " " + pathWithQuery + " HTTP/1.1\r\nHost: h\r\n"
		if body != "" {
			r += "Content-Type: application/json\r\n"
		}
		return r + "\r\n" + body
	}
	hist := []devicelab.Exchange{
		// login produces a userId
		{Method: "POST", Host: "h", Path: "/login", Request: req("POST", "/login", `{"user":"alice"}`), Response: resp(`{"user_id":"990011"}`)},
		// accounts list produces an account id
		{Method: "GET", Host: "h", Path: "/accounts", Request: req("GET", "/accounts", ""), Response: resp(`{"account_id":"100345"}`)},
		// statement consumes the account id in its path -> depends on /accounts
		{Method: "GET", Host: "h", Path: "/accounts/100345/statement", Request: req("GET", "/accounts/100345/statement", ""), Response: resp(`{"ok":true}`)},
	}
	nodes, edges := buildAPIGraph(hist)
	if len(nodes) != 3 {
		t.Fatalf("nodes = %d want 3", len(nodes))
	}
	// expect an edge GET /accounts -> GET /accounts/{id}/statement via 100345
	found := false
	for _, e := range edges {
		if e.From == "GET /accounts" && e.To == "GET /accounts/{id}/statement" && e.Via == "100345" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected dependency edge /accounts -> /accounts/{id}/statement, got %+v", edges)
	}
	// the statement endpoint's object is "statement"
	for _, n := range nodes {
		if n.Endpoint == "GET /accounts/{id}/statement" && n.Object != "statement" {
			t.Errorf("statement object = %q", n.Object)
		}
	}
}
