package agent

import "testing"

func TestLuhnValid(t *testing.T) {
	if !luhnValid("4242424242424242") { // test Visa, Luhn-valid
		t.Error("valid PAN not accepted")
	}
	if luhnValid("4242424242424243") {
		t.Error("invalid checksum accepted")
	}
	if luhnValid("123") {
		t.Error("too short accepted")
	}
}

func TestSensitiveValue(t *testing.T) {
	// card/SSN/JWT are sensitive but may be the caller's own data: detected, not confirmed.
	if kind, conf := sensitiveValue("4242 4242 4242 4242"); kind != "card number (PAN)" || conf {
		t.Errorf("PAN: got (%q,%v), want (card number (PAN), false)", kind, conf)
	}
	if kind, conf := sensitiveValue("123-45-6789"); kind != "SSN" || conf {
		t.Errorf("SSN: got (%q,%v), want (SSN, false)", kind, conf)
	}
	if kind, conf := sensitiveValue("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcDEF123"); kind != "JWT" || conf {
		t.Errorf("JWT: got (%q,%v), want (JWT, false)", kind, conf)
	}
	// a private key is never legitimate in a response: confirmed on presence.
	if kind, conf := sensitiveValue("-----BEGIN RSA PRIVATE KEY-----"); kind != "private key" || !conf {
		t.Errorf("private key: got (%q,%v), want (private key, true)", kind, conf)
	}
	if kind, _ := sensitiveValue("just a normal string"); kind != "" {
		t.Error("false positive on normal string")
	}
	// a plain long number that fails Luhn must not be flagged as a PAN
	if kind, _ := sensitiveValue("1111111111111111"); kind == "card number (PAN)" {
		t.Error("non-Luhn number wrongly flagged as PAN")
	}
}

func TestSensitiveFieldsInJSON(t *testing.T) {
	body := `{"user":{"name":"alice","password":"hunter2","ssn":"123-45-6789"},"card":"4242424242424242","note":""}`
	confirmed, unverified := sensitiveFieldsInJSON(body)
	cj, uj := join(confirmed), join(unverified)
	if !contains(cj, "password") {
		t.Fatalf("password must be confirmed, got confirmed=%v", confirmed)
	}
	if !contains(uj, "SSN") || !contains(uj, "card number") {
		t.Fatalf("ssn+pan must be unverified, got unverified=%v", unverified)
	}
	// empty sensitive field should NOT be flagged
	ec, eu := sensitiveFieldsInJSON(`{"password":"","data":"ok"}`)
	if len(ec)+len(eu) != 0 {
		t.Errorf("empty password should not be flagged: %v %v", ec, eu)
	}
}

// TestLoginResponseNotConfirmed locks finding #1: a legitimate login/refresh
// response returns a JWT by design, so it must never auto-file a confirmed finding.
func TestLoginResponseNotConfirmed(t *testing.T) {
	login := `{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sIg_abcDEF123","expires_in":3600}`
	confirmed, unverified := sensitiveFieldsInJSON(login)
	if len(confirmed) != 0 {
		t.Fatalf("login response must not be confirmed, got %v", confirmed)
	}
	if len(unverified) == 0 {
		t.Fatalf("JWT should still be reported for verification")
	}
}

func join(ss []string) string {
	out := ""
	for _, s := range ss {
		out += s + "|"
	}
	return out
}
