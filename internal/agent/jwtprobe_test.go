package agent

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// makeJWT builds an unsigned-shape token (header.payload.sig) for testing decode
// and forgery helpers; sig is arbitrary since nothing here verifies it.
func makeJWT(header, payload map[string]any, sig string) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p) + "." + sig
}

func TestBearerToken(t *testing.T) {
	raw := "GET /x HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer abc.def.ghi\r\n\r\n"
	if got := bearerToken(raw); got != "abc.def.ghi" {
		t.Fatalf("bearerToken = %q", got)
	}
	if bearerToken("GET /x HTTP/1.1\r\nHost: h\r\n\r\n") != "" {
		t.Error("expected empty token when no auth header")
	}
}

func TestDecodeJWTAndStaticIssues(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	tok := makeJWT(map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "alice", "exp": float64(now.Unix() - 10)}, "sig")
	h, p, sig, ok := decodeJWT(tok)
	if !ok || h["alg"] != "HS256" || p["sub"] != "alice" || sig != "sig" {
		t.Fatalf("decode failed: %v %v %q %v", h, p, sig, ok)
	}
	issues := jwtStaticIssues(h, p, now)
	joined := ""
	for _, s := range issues {
		joined += s + "|"
	}
	if !contains(joined, "expired") || !contains(joined, "symmetric") {
		t.Fatalf("expected expired + symmetric issues, got %v", issues)
	}
	// no-exp token
	tok2 := makeJWT(map[string]any{"alg": "RS256"}, map[string]any{"sub": "x"}, "s")
	h2, p2, _, _ := decodeJWT(tok2)
	hasNoExp := false
	for _, s := range jwtStaticIssues(h2, p2, now) {
		if contains(s, "no exp") {
			hasNoExp = true
		}
	}
	if !hasNoExp {
		t.Error("expected 'no exp' issue")
	}
	// malformed
	if _, _, _, ok := decodeJWT("not.a"); ok {
		t.Error("two-part token must not decode")
	}
}

func TestForgeAlgNoneAndTamper(t *testing.T) {
	tok := makeJWT(map[string]any{"alg": "HS256"}, map[string]any{"sub": "alice", "role": "user"}, "realsig")
	forged, ok := forgeAlgNone(tok)
	if !ok {
		t.Fatal("forgeAlgNone failed")
	}
	h, p, sig, ok := decodeJWT(forged)
	if !ok || h["alg"] != "none" || p["sub"] != "alice" || sig != "" {
		t.Fatalf("alg:none forgery wrong: %v sig=%q", h, sig)
	}
	tampered, ok := tamperSignature(tok)
	if !ok {
		t.Fatal("tamperSignature failed")
	}
	if tampered == tok {
		t.Error("tampered token equals original")
	}
	_, _, sig2, _ := decodeJWT(tampered)
	if sig2 == "realsig" {
		t.Error("signature not changed")
	}
	// payload/header preserved under tamper
	hh, pp, _, _ := decodeJWT(tampered)
	if hh["alg"] != "HS256" || pp["sub"] != "alice" {
		t.Error("tamper changed header/payload")
	}
}
