package agent

import "testing"

func TestResponseHeader(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://x\r\nContent-Type: application/json\r\n\r\n{}"
	if responseHeader(resp, "access-control-allow-origin") != "https://x" {
		t.Error("case-insensitive header read failed")
	}
	if responseHeader(resp, "X-Missing") != "" {
		t.Error("absent header should be empty")
	}
}

func TestCorsVerdict(t *testing.T) {
	origin := "https://evil.attacker.example"
	// reflected + credentials -> critical
	if v, s, _ := corsVerdict(origin, "true", origin); !v || s != "critical" {
		t.Errorf("reflected+creds should be critical, got %v %q", v, s)
	}
	// reflected, no creds -> high
	if v, s, _ := corsVerdict(origin, "", origin); !v || s != "high" {
		t.Errorf("reflected should be high, got %v %q", v, s)
	}
	// null origin allowed
	if v, _, _ := corsVerdict("null", "", "null"); !v {
		t.Error("null origin should be flagged")
	}
	// wildcard + creds
	if v, s, _ := corsVerdict("*", "true", origin); !v || s != "medium" {
		t.Errorf("wildcard+creds should be medium, got %v %q", v, s)
	}
	// safe: wildcard without creds (allowed for public APIs)
	if v, _, _ := corsVerdict("*", "", origin); v {
		t.Error("wildcard without credentials must not be flagged")
	}
	// safe: specific trusted origin not equal to attacker
	if v, _, _ := corsVerdict("https://trusted.app", "true", origin); v {
		t.Error("a non-reflected trusted origin must not be flagged")
	}
}
