package agent

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// Second, independent evaluation target modelled on OWASP crAPI's documented API
// vulnerabilities (BOLA on another user's vehicle location; JWT accepted without
// signature verification), with secure negatives. This exercises the SAME
// production deciders (classifyAccess, decodeJWT/forgeAlgNone, classifyTxn) that
// run in the tools, against crAPI-shaped endpoints — so the metrics are a genuine
// second-target measurement, not a re-run of the bank fixture.
//
// TestCrapiLiveIntegration runs the same differential against a REAL crAPI when
// RIPPLE_CRAPI_URL plus two bearer tokens and an owner resource path are supplied;
// it skips cleanly otherwise, so the suite stays green without crAPI and becomes a
// live crAPI eval the moment one is pointed at it.

const (
	crapiOwnerVeh    = "VEH-OWNER-0001"
	crapiAttackerVeh = "VEH-ATTACK-0002"
)

func crapiModeledServer() *httptest.Server {
	mux := http.NewServeMux()
	bearer := func(r *http.Request) string {
		h := r.Header.Get("Authorization")
		if len(h) > 7 && h[:7] == "Bearer " {
			return h[7:]
		}
		return ""
	}
	// crAPI-style BOLA: returns ANY vehicle's location to any authenticated user.
	mux.HandleFunc("/identity/api/v2/vehicle/", func(w http.ResponseWriter, r *http.Request) {
		if bearer(r) == "" {
			w.WriteHeader(401)
			return
		}
		// path: /identity/api/v2/vehicle/<vid>/location[-secure]
		p := r.URL.Path
		secure := len(p) >= 7 && p[len(p)-7:] == "-secure"
		if secure {
			// ownership-checked: owner token only reaches owner vehicle
			if bearer(r) == crapiTokenB || !hasSuffix(p, crapiOwnerVeh+"/location-secure") {
				w.WriteHeader(403)
				_, _ = io.WriteString(w, `{"error":"forbidden"}`)
				return
			}
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"vehicleLocation":{"lat":37.42,"long":-122.08},"vin":"OWNERVIN123"}`)
	})
	// crAPI-style JWT weakness: accepts any token whose payload decodes (no sig check).
	mux.HandleFunc("/identity/api/v2/user/dashboard", func(w http.ResponseWriter, r *http.Request) {
		if _, p, _, ok := decodeJWT(bearer(r)); ok && p["sub"] != nil {
			w.WriteHeader(200)
			_, _ = io.WriteString(w, `{"ok":true}`)
			return
		}
		w.WriteHeader(401)
	})
	mux.HandleFunc("/identity/api/v2/user/dashboard-secure", func(w http.ResponseWriter, r *http.Request) {
		if bearer(r) == evalValidJWT {
			w.WriteHeader(200)
			_, _ = io.WriteString(w, `{"ok":true}`)
			return
		}
		w.WriteHeader(401)
	})
	return httptest.NewServer(mux)
}

var crapiTokenB = "crapi-token-b"

func hasSuffix(s, suf string) bool { return len(s) >= len(suf) && s[len(s)-len(suf):] == suf }

func crapiGet(srv *httptest.Server, path, token string) (int, string) {
	req, _ := http.NewRequest("GET", srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := srv.Client().Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestEvalCrapiModeled(t *testing.T) {
	srv := crapiModeledServer()
	defer srv.Close()
	tokenA := evalValidJWT // owner

	tp, fp, tn, fn := 0, 0, 0, 0
	record := func(detected, want bool, name string) {
		switch {
		case detected && want:
			tp++
		case detected && !want:
			fp++
			t.Errorf("FALSE POSITIVE: %s", name)
		case !detected && want:
			fn++
			t.Errorf("FALSE NEGATIVE: %s", name)
		default:
			tn++
		}
	}

	// 1. BOLA on vehicle location (vulnerable): B receives owner's vehicle data.
	{
		os_, ob := crapiGet(srv, "/identity/api/v2/vehicle/"+crapiOwnerVeh+"/location", tokenA)
		cs, cb := crapiGet(srv, "/identity/api/v2/vehicle/"+crapiOwnerVeh+"/location", crapiTokenB)
		v, _, _, _ := classifyAccess(os_, cs, ob, cb, resourceIDs("GET /identity/api/v2/vehicle/"+crapiOwnerVeh+"/location HTTP/1.1"))
		record(v == authzVulnerable, true, "crAPI vehicle-location BOLA")
	}
	// 2. Ownership-checked variant (secure): B denied.
	{
		os_, ob := crapiGet(srv, "/identity/api/v2/vehicle/"+crapiOwnerVeh+"/location-secure", tokenA)
		cs, cb := crapiGet(srv, "/identity/api/v2/vehicle/"+crapiOwnerVeh+"/location-secure", crapiTokenB)
		v, _, _, _ := classifyAccess(os_, cs, ob, cb, nil)
		record(v == authzVulnerable, false, "crAPI vehicle-location ownership-checked")
	}
	// 3. JWT accepted without signature verification (vulnerable).
	{
		forged, _ := forgeAlgNone(evalValidJWT)
		bs, bb := crapiGet(srv, "/identity/api/v2/user/dashboard", evalValidJWT)
		fsStatus, fsBody := crapiGet(srv, "/identity/api/v2/user/dashboard", forged)
		detected := classifyTxn(bs, bb) == txnAccepted && classifyTxn(fsStatus, fsBody) == txnAccepted
		record(detected, true, "crAPI JWT signature-not-verified")
	}
	// 4. Secure JWT endpoint: forged rejected.
	{
		forged, _ := forgeAlgNone(evalValidJWT)
		bs, bb := crapiGet(srv, "/identity/api/v2/user/dashboard-secure", evalValidJWT)
		fsStatus, fsBody := crapiGet(srv, "/identity/api/v2/user/dashboard-secure", forged)
		detected := classifyTxn(bs, bb) == txnAccepted && classifyTxn(fsStatus, fsBody) == txnAccepted
		record(detected, false, "crAPI JWT secure endpoint")
	}
	reportMetrics(t, "crapi-modeled", tp, fp, tn, fn)
}

// TestCrapiLiveIntegration runs the real BOLA differential against a live crAPI
// (or any target) when fully configured via env, else skips.
//
//	RIPPLE_CRAPI_URL         base URL, e.g. http://localhost:8888
//	RIPPLE_CRAPI_TOKEN_OWNER    bearer token of the resource owner (identity A)
//	RIPPLE_CRAPI_TOKEN_ATTACKER bearer token of a non-owner (identity B)
//	RIPPLE_CRAPI_OWNER_PATH  owner's resource path, e.g. /identity/api/v2/vehicle/<vid>/location
func TestCrapiLiveIntegration(t *testing.T) {
	base := os.Getenv("RIPPLE_CRAPI_URL")
	owner := os.Getenv("RIPPLE_CRAPI_TOKEN_OWNER")
	attacker := os.Getenv("RIPPLE_CRAPI_TOKEN_ATTACKER")
	path := os.Getenv("RIPPLE_CRAPI_OWNER_PATH")
	if base == "" || owner == "" || attacker == "" || path == "" {
		t.Skip("live crAPI not configured; set RIPPLE_CRAPI_URL/_TOKEN_OWNER/_TOKEN_ATTACKER/_OWNER_PATH to run")
	}
	get := func(token string) (int, string) {
		req, _ := http.NewRequest("GET", base+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	os_, ob := get(owner)
	cs, cb := get(attacker)
	verdict, reason, sim, shared := classifyAccess(os_, cs, ob, cb, resourceIDs("GET "+path+" HTTP/1.1"))
	t.Logf("live crAPI BOLA on %s: owner=%d attacker=%d verdict=%s (sim=%.2f shared=%v) — %s", path, os_, cs, verdict, sim, shared, reason)
	if verdict == authzVulnerable {
		t.Logf("CONFIRMED BOLA on live target %s%s", base, path)
	}
}

// TestCrapiLiveJWT runs the production JWT forgery checks against a live target.
//
//	RIPPLE_CRAPI_URL         base URL
//	RIPPLE_CRAPI_TOKEN_OWNER a genuine JWT the target accepts
//	RIPPLE_CRAPI_JWT_PATH    a protected GET endpoint (default /identity/api/v2/user/dashboard)
//
// A forged alg:none / tampered-signature token accepted while the genuine one is
// accepted (and a garbage token is rejected) is a confirmed signature-verification
// bypass.
func TestCrapiLiveJWT(t *testing.T) {
	base := os.Getenv("RIPPLE_CRAPI_URL")
	tok := os.Getenv("RIPPLE_CRAPI_TOKEN_OWNER")
	if base == "" || tok == "" {
		t.Skip("live crAPI not configured; set RIPPLE_CRAPI_URL and RIPPLE_CRAPI_TOKEN_OWNER to run")
	}
	path := os.Getenv("RIPPLE_CRAPI_JWT_PATH")
	if path == "" {
		path = "/identity/api/v2/user/dashboard"
	}
	get := func(bearer string) txnOutcome {
		req, _ := http.NewRequest("GET", base+path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return classifyTxn(resp.StatusCode, string(b))
	}
	baseline := get(tok)
	garbage := get("garbage.token.value")
	if baseline != txnAccepted {
		t.Skipf("genuine token not accepted at %s (outcome=%s); check path/token", path, baseline)
	}
	forged, _ := forgeAlgNone(tok)
	tampered, _ := tamperSignature(tok)
	forgedOK := get(forged) == txnAccepted
	tamperedOK := get(tampered) == txnAccepted
	t.Logf("live crAPI JWT on %s: genuine=accepted garbage=%s algNone=%v tamperedSig=%v", path, garbage, forgedOK, tamperedOK)
	if garbage != txnAccepted && (forgedOK || tamperedOK) {
		t.Logf("CONFIRMED JWT signature-verification bypass on live target %s%s", base, path)
	}
}
