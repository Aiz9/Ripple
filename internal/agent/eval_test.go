package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/internal/devicelab"
)

// Controlled evaluation against ground truth.
//
// This harness stands up an intentionally-vulnerable bank API with KNOWN seeded
// flaws and known-secure negatives, then runs the engine's REAL deterministic
// decision logic (classifyAccess for authz, classifyTxn + invariants for business
// logic) against its live responses — the same functions the production tools use.
// It measures precision/recall/false-positive rate so detection quality is
// reported from measurement, not asserted by hand. No Burp/device needed because
// the deciders are pure over HTTP status+body.

// seeded test accounts
const (
	tokA     = "tokA" // owns account 100 (alice)
	tokB     = "tokB" // owns account 200 (bob)
	tokAdmin = "tokAdmin"
)

func ownerOfToken(tok string) string {
	switch tok {
	case tokA:
		return "alice:100"
	case tokB:
		return "bob:200"
	case tokAdmin:
		return "admin"
	}
	return ""
}

// seededBank returns a server with documented, ground-truthed behavior.
func seededBank() *httptest.Server {
	seenIdem := map[string]bool{}
	mux := http.NewServeMux()
	auth := func(r *http.Request) string {
		return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}

	// VULN (IDOR/BOLA): returns any account's data to any authenticated caller.
	mux.HandleFunc("/accounts/", func(w http.ResponseWriter, r *http.Request) {
		if auth(r) == "" {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/accounts/")
		owner := "alice"
		if id == "200" {
			owner = "bob"
		}
		writeJSON(w, 200, map[string]any{"account": id, "owner": owner, "balance": 4200})
	})
	// SECURE: statement only for the owner of the account.
	mux.HandleFunc("/statements/", func(w http.ResponseWriter, r *http.Request) {
		tok := auth(r)
		if tok == "" {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/statements/")
		owns := (tok == tokA && id == "100") || (tok == tokB && id == "200")
		if !owns {
			writeJSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}
		writeJSON(w, 200, map[string]any{"statement": id, "lines": []string{"x"}})
	})
	// SECURE: returns the CALLER's own profile (different per identity).
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		tok := auth(r)
		if tok == "" {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		writeJSON(w, 200, map[string]any{"me": ownerOfToken(tok)})
	})
	// VULN (missing authentication): leaks account 100 even with no auth.
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"account": "100", "owner": "alice", "balance": 4200})
	})
	// LEGITIMATELY SHARED: same content for every authenticated user (401 unauth).
	// Without a configured expectation this looks like IDOR (identical body to
	// another principal); with one it must not be flagged.
	mux.HandleFunc("/announcements", func(w http.ResponseWriter, r *http.Request) {
		if auth(r) == "" {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		writeJSON(w, 200, map[string]any{"announcements": []string{"maintenance sunday", "new feature"}})
	})
	// VULN (SSTI): evaluates {{a*b}} in the q param. SECURE: reflects literally.
	mux.HandleFunc("/render/insecure", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if a, b, ok := parseMul(q); ok {
			writeJSON(w, 200, map[string]any{"rendered": a * b})
			return
		}
		writeJSON(w, 200, map[string]any{"rendered": q})
	})
	mux.HandleFunc("/render/secure", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"rendered": r.URL.Query().Get("q")}) // literal reflect
	})
	// VULN (error-based SQLi): leaks a DB error when q contains a quote. SECURE: 200.
	mux.HandleFunc("/search/insecure", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("q"), "'") {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, `You have an error in your SQL syntax near "'"`)
			return
		}
		writeJSON(w, 200, map[string]any{"results": []string{}})
	})
	mux.HandleFunc("/search/secure", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"results": []string{}})
	})
	// VULN (mass assignment): echoes back whatever fields the client sends, so an
	// injected "role":"admin" is applied. SECURE variant binds an allow-list only.
	mux.HandleFunc("/profile/insecure", func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &p)
		p["id"] = 1
		writeJSON(w, 200, p) // binds everything the client sent
	})
	mux.HandleFunc("/profile/secure", func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &p)
		out := map[string]any{"id": 1, "role": "user"} // allow-list: name only; role server-set
		if n, ok := p["name"]; ok {
			out["name"] = n
		}
		writeJSON(w, 200, out)
	})
	// VULN: 500s when amount is not a number (unhandled malformed input). SECURE
	// variant rejects with 400.
	mux.HandleFunc("/charge/insecure", func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &p)
		if _, ok := p["amount"].(float64); !ok { // non-number / missing -> unhandled path
			w.WriteHeader(500)
			return
		}
		writeJSON(w, 200, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/charge/secure", func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &p)
		if _, ok := p["amount"].(float64); !ok {
			writeJSON(w, 400, map[string]string{"error": "amount must be a number"})
			return
		}
		writeJSON(w, 200, map[string]any{"status": "ok"})
	})
	// VULN (race/TOCTOU): single-use redeem with NO serialization — every concurrent
	// caller is accepted. SECURE variant locks so only the first succeeds.
	mux.HandleFunc("/redeem/insecure", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "completed"})
	})
	var redeemMu sync.Mutex
	redeemed := false
	mux.HandleFunc("/redeem/secure", func(w http.ResponseWriter, r *http.Request) {
		redeemMu.Lock()
		defer redeemMu.Unlock()
		if redeemed {
			writeJSON(w, 409, map[string]string{"error": "already redeemed"})
			return
		}
		redeemed = true
		writeJSON(w, 200, map[string]any{"status": "completed"})
	})
	// VULN: decodes the JWT but does NOT verify its signature — accepts alg:none.
	mux.HandleFunc("/jwt/insecure", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if _, p, _, ok := decodeJWT(tok); ok && p["sub"] != nil {
			writeJSON(w, 200, map[string]any{"ok": true})
			return
		}
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
	})
	// SECURE: accepts only the exact issued token (stands in for signature check).
	mux.HandleFunc("/jwt/secure", func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == evalValidJWT {
			writeJSON(w, 200, map[string]any{"ok": true})
			return
		}
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
	})
	// SECURE: admin-only report.
	mux.HandleFunc("/admin/report", func(w http.ResponseWriter, r *http.Request) {
		tok := auth(r)
		if tok == "" {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if tok != tokAdmin {
			writeJSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}
		writeJSON(w, 200, map[string]any{"report": "ok"})
	})
	// VULN: accepts any amount (negative/over-limit) and reprocesses duplicates.
	mux.HandleFunc("/transfer", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "completed", "txn": fmt.Sprintf("%d", len(seenIdem))})
	})
	// SECURE: enforces amount>0, limit, currency and idempotency.
	mux.HandleFunc("/transfer-secure", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p struct {
			Amount   float64 `json:"amount"`
			Currency string  `json:"currency"`
			Idem     string  `json:"idem"`
		}
		_ = json.Unmarshal(body, &p)
		if p.Amount <= 0 || p.Amount > 10000 {
			writeJSON(w, 400, map[string]string{"error": "invalid amount"})
			return
		}
		if p.Currency != "USD" && p.Currency != "EUR" {
			writeJSON(w, 400, map[string]string{"error": "invalid currency"})
			return
		}
		if p.Idem != "" && seenIdem[p.Idem] {
			writeJSON(w, 200, map[string]string{"status": "already_processed"})
			return
		}
		seenIdem[p.Idem] = true
		writeJSON(w, 200, map[string]any{"status": "completed", "txn": "s1"})
	})
	return httptest.NewServer(mux)
}

func getReq(srv *httptest.Server, path, token string) (int, string) {
	req, _ := http.NewRequest("GET", srv.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func postReq(srv *httptest.Server, path, body string) (int, string) {
	resp, err := srv.Client().Post(srv.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestEvalAuthzGroundTruth(t *testing.T) {
	srv := seededBank()
	defer srv.Close()

	// path, owner token, candidate token ("" = unauthenticated), reqLineForIDs, groundTruthVulnerable
	cases := []struct {
		name, path, owner, cand, reqLine string
		wantVuln                         bool
	}{
		{"idor-accounts", "/accounts/100", tokA, tokB, "GET /accounts/100 HTTP/1.1", true},
		{"secure-statements", "/statements/100", tokA, tokB, "GET /statements/100 HTTP/1.1", false},
		{"secure-own-profile", "/profile", tokA, tokB, "GET /profile HTTP/1.1", false},
		{"missing-auth-me", "/me", tokA, "", "GET /me HTTP/1.1", true},
		{"secure-admin", "/admin/report", tokAdmin, tokB, "GET /admin/report HTTP/1.1", false},
	}

	var tp, fp, tn, fn int
	for _, c := range cases {
		os, ob := getReq(srv, c.path, c.owner)
		cs, cb := getReq(srv, c.path, c.cand)
		verdict, reason, _, _ := classifyAccess(os, cs, ob, cb, resourceIDs(c.reqLine))
		detected := verdict == authzVulnerable
		switch {
		case detected && c.wantVuln:
			tp++
		case detected && !c.wantVuln:
			fp++
			t.Errorf("FALSE POSITIVE on %s: %s", c.name, reason)
		case !detected && c.wantVuln:
			fn++
			t.Errorf("FALSE NEGATIVE on %s (verdict=%s): %s", c.name, verdict, reason)
		default:
			tn++
		}
	}
	reportMetrics(t, "authz", tp, fp, tn, fn)
}

// evalValidJWT is the genuine token the secure endpoint accepts.
var evalValidJWT = makeJWT(map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": "alice", "role": "user"}, "genuine_sig")

func TestEvalJWTBypassGroundTruth(t *testing.T) {
	srv := seededBank()
	defer srv.Close()

	forged, ok := forgeAlgNone(evalValidJWT)
	if !ok {
		t.Fatal("could not forge alg:none token")
	}
	tampered, _ := tamperSignature(evalValidJWT)

	// detect: baseline accepts the genuine token, and a must-reject token is accepted.
	detectBypass := func(path string) bool {
		bs, bb := getReq(srv, path, evalValidJWT)
		if classifyTxn(bs, bb) != txnAccepted {
			return false // no baseline
		}
		for _, bad := range []string{forged, tampered} {
			s, b := getReq(srv, path, bad)
			if classifyTxn(s, b) == txnAccepted {
				return true
			}
		}
		return false
	}

	tp, fp, tn, fn := 0, 0, 0, 0
	if detectBypass("/jwt/insecure") {
		tp = 1
	} else {
		fn = 1
		t.Error("FALSE NEGATIVE: /jwt/insecure accepts forged tokens but was not detected")
	}
	if detectBypass("/jwt/secure") {
		fp = 1
		t.Error("FALSE POSITIVE: /jwt/secure flagged though it rejects forged tokens")
	} else {
		tn = 1
	}
	reportMetrics(t, "jwt-auth", tp, fp, tn, fn)
}

// parseMul extracts "<a>*<b>" from a template payload like {{1009*1013}} and
// returns the two integers (simulating a template engine evaluating the product).
func parseMul(s string) (int, int, bool) {
	i := strings.IndexByte(s, '*')
	if i < 0 {
		return 0, 0, false
	}
	digits := func(x string) int {
		n := 0
		seen := false
		for _, r := range x {
			if r >= '0' && r <= '9' {
				n = n*10 + int(r-'0')
				seen = true
			}
		}
		if !seen {
			return -1
		}
		return n
	}
	a, b := digits(s[:i]), digits(s[i+1:])
	if a < 0 || b < 0 {
		return 0, 0, false
	}
	return a, b, true
}

func TestEvalInjectionGroundTruth(t *testing.T) {
	srv := seededBank()
	defer srv.Close()

	ssti := func(path string) bool {
		for _, p := range sstiPayloads() {
			_, b := getReq(srv, path+"?q="+url.QueryEscape(p), tokA)
			if detectSSTI(b) {
				return true
			}
		}
		return false
	}
	sqli := func(path string) bool {
		for _, p := range sqlPayloads {
			_, b := getReq(srv, path+"?q="+url.QueryEscape(p), tokA)
			if detectSQLError(b) {
				return true
			}
		}
		return false
	}

	tp, fp, tn, fn := 0, 0, 0, 0
	rec := func(detected, want bool, name string) {
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
	rec(ssti("/render/insecure"), true, "SSTI render/insecure")
	rec(ssti("/render/secure"), false, "SSTI render/secure (literal reflect)")
	rec(sqli("/search/insecure"), true, "SQLi search/insecure")
	rec(sqli("/search/secure"), false, "SQLi search/secure")
	reportMetrics(t, "injection", tp, fp, tn, fn)
}

func TestEvalMassAssignmentGroundTruth(t *testing.T) {
	srv := seededBank()
	defer srv.Close()
	base := `{"name":"alice"}`
	// Detect: inject role=admin; applied iff the response reflects it.
	detect := func(path string) bool {
		nb, _ := addOrSetJSONField(base, "role", `"admin"`)
		s, b := postReq(srv, path, nb)
		return s >= 200 && s < 300 && reflectsInjected(b, "role", `"admin"`)
	}
	tp, fp, tn, fn := 0, 0, 0, 0
	if detect("/profile/insecure") {
		tp = 1
	} else {
		fn = 1
		t.Error("FALSE NEGATIVE: /profile/insecure binds injected role but was not detected")
	}
	if detect("/profile/secure") {
		fp = 1
		t.Error("FALSE POSITIVE: /profile/secure allow-lists fields but was flagged")
	} else {
		tn = 1
	}
	reportMetrics(t, "mass-assignment", tp, fp, tn, fn)
}

func TestEvalSchemaFuzzGroundTruth(t *testing.T) {
	srv := seededBank()
	defer srv.Close()
	base := `{"amount":100,"note":"hi"}`
	muts := bodyMutations(base)
	if len(muts) == 0 {
		t.Fatal("no mutations generated")
	}
	// Any mutation that produces a 5xx is a robustness violation.
	anyServerError := func(path string) bool {
		for _, m := range muts {
			s, _ := postReq(srv, path, m.body)
			if isServerError(s) {
				return true
			}
		}
		return false
	}
	tp, fp, tn, fn := 0, 0, 0, 0
	if anyServerError("/charge/insecure") {
		tp = 1
	} else {
		fn = 1
		t.Error("FALSE NEGATIVE: /charge/insecure 500s on malformed input but was not detected")
	}
	if anyServerError("/charge/secure") {
		fp = 1
		t.Error("FALSE POSITIVE: /charge/secure validates input (4xx) but was flagged")
	} else {
		tn = 1
	}
	reportMetrics(t, "schema-fuzz", tp, fp, tn, fn)
}

func TestEvalOpenAPIGroundTruth(t *testing.T) {
	spec := `{
      "openapi":"3.0.0",
      "servers":[{"url":"https://api.bank.test/v2"}],
      "security":[{"bearer":[]}],
      "paths":{
        "/accounts/{accountId}":{"get":{"parameters":[{"name":"accountId","in":"path"}]}},
        "/accounts/{accountId}/statement":{"get":{"parameters":[{"name":"accountId","in":"path"},{"name":"from","in":"query"}]}},
        "/transfers":{"post":{"requestBody":{"content":{"application/json":{"schema":{"properties":{"amount":{},"to":{}}}}}}}}
      }
    }`
	eps, err := parseOpenAPI([]byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	// Ground truth: 3 endpoints with these normalized keys, all auth-required (global).
	want := map[string]bool{
		"GET /v2/accounts/{id}":           false,
		"GET /v2/accounts/{id}/statement": false,
		"POST /v2/transfers":              false,
	}
	for i := range eps {
		k := eps[i].Method + " " + eps[i].Path
		if _, ok := want[k]; ok {
			want[k] = true
			if !eps[i].AuthRequired {
				t.Errorf("%s should be auth-required (global security)", k)
			}
		} else {
			t.Errorf("unexpected endpoint parsed: %s", k)
		}
	}
	covered := 0
	for k, found := range want {
		if found {
			covered++
		} else {
			t.Errorf("MISSED documented endpoint %s", k)
		}
	}
	t.Logf("openapi ingest: %d/%d documented endpoints parsed & normalized (coverage %d/%d)", len(eps), len(want), covered, len(want))
}

func TestEvalAPIGraphGroundTruth(t *testing.T) {
	resp := func(body string) string { return "HTTP/1.1 200 OK\r\n\r\n" + body }
	rq := func(method, pathWithQuery string) string {
		return method + " " + pathWithQuery + " HTTP/1.1\r\nHost: bank\r\n\r\n"
	}
	hist := []devicelab.Exchange{
		{Method: "GET", Host: "bank", Path: "/accounts", Request: rq("GET", "/accounts"), Response: resp(`{"account_id":"100345","balance":4200}`)},
		{Method: "GET", Host: "bank", Path: "/accounts/100345/statement", Request: rq("GET", "/accounts/100345/statement"), Response: resp(`{"ok":true}`)},
		{Method: "GET", Host: "bank", Path: "/accounts/100345/beneficiaries", Request: rq("GET", "/accounts/100345/beneficiaries"), Response: resp(`{"items":[]}`)},
	}
	nodes, edges := buildAPIGraph(hist)

	// Ground truth: two dependency edges from /accounts via the account id; no edge
	// invented from the balance (not an id key).
	wantEdges := map[string]bool{
		"GET /accounts->GET /accounts/{id}/statement":     false,
		"GET /accounts->GET /accounts/{id}/beneficiaries": false,
	}
	for _, e := range edges {
		k := e.From + "->" + e.To
		if _, ok := wantEdges[k]; ok {
			if e.Via != "100345" {
				t.Errorf("edge %s via %q, want 100345", k, e.Via)
			}
			wantEdges[k] = true
		} else {
			t.Errorf("unexpected (false) dependency edge: %s via %s", k, e.Via)
		}
	}
	for k, found := range wantEdges {
		if !found {
			t.Errorf("missing expected dependency edge %s", k)
		}
	}
	// object identification
	objOK := false
	for _, n := range nodes {
		if n.Endpoint == "GET /accounts/{id}/beneficiaries" && n.Object == "beneficiaries" {
			objOK = true
		}
	}
	if !objOK {
		t.Error("beneficiaries object not identified")
	}
	t.Logf("api-graph: %d nodes, %d dependency edges, 0 false edges (balance not treated as id)", len(nodes), len(edges))
}

func TestEvalWorkflowGroundTruth(t *testing.T) {
	steps := []workflowStep{
		{State: "initiate", Method: "POST", Pattern: "/transfers"},
		{State: "verify", Method: "POST", Pattern: "/transfers/{id}/otp"},
		{State: "confirm", Method: "POST", Pattern: "/transfers/{id}/confirm"},
	}
	order := stateIndex([]string{"initiate", "verify", "confirm"})
	req := func(method, pathWithQuery string) string {
		return method + " " + pathWithQuery + " HTTP/1.1\r\nHost: bank\r\n\r\n"
	}
	ok200 := "HTTP/1.1 200 OK\r\n\r\n{}"
	// T1 secure: initiate -> verify -> confirm. T2 vuln: initiate -> confirm (skips verify).
	hist := []devicelab.Exchange{
		{Method: "POST", Host: "bank", Path: "/transfers", Request: req("POST", "/transfers?transaction_id=T1"), Response: ok200},
		{Method: "POST", Host: "bank", Path: "/transfers/10/otp", Request: req("POST", "/transfers/10/otp?transaction_id=T1"), Response: ok200},
		{Method: "POST", Host: "bank", Path: "/transfers/10/confirm", Request: req("POST", "/transfers/10/confirm?transaction_id=T1"), Response: ok200},
		{Method: "POST", Host: "bank", Path: "/transfers", Request: req("POST", "/transfers?transaction_id=T2"), Response: ok200},
		{Method: "POST", Host: "bank", Path: "/transfers/20/confirm", Request: req("POST", "/transfers/20/confirm?transaction_id=T2"), Response: ok200},
	}
	// Replicate the handler's accepted-step grouping, then apply the production verdict.
	groups := map[string][]string{}
	var keys []string
	for _, ex := range hist {
		method, canon, ok := exchangeEndpoint(ex)
		if !ok {
			continue
		}
		state, ok := classifyStep(steps, method, pathOf(canon))
		if !ok || classifyTxn(httpStatus(ex.Response), httpBody(ex.Response)) != txnAccepted {
			continue
		}
		k := fieldValue(ex.Request, "transaction_id")
		if _, seen := groups[k]; !seen {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], state)
	}
	flagged := map[string]bool{}
	for _, k := range keys {
		if len(seqViolations(order, groups[k])) > 0 {
			flagged[k] = true
		}
	}
	gt := map[string]bool{"T1": false, "T2": true}
	tp, fp, tn, fn := 0, 0, 0, 0
	for k, want := range gt {
		switch {
		case flagged[k] && want:
			tp++
		case flagged[k] && !want:
			fp++
			t.Errorf("FALSE POSITIVE: in-order object %s flagged", k)
		case !flagged[k] && want:
			fn++
			t.Errorf("FALSE NEGATIVE: skipped-step object %s not flagged (seq=%v)", k, groups[k])
		default:
			tn++
		}
	}
	reportMetrics(t, "workflow", tp, fp, tn, fn)
}

func TestEvalRaceConditionGroundTruth(t *testing.T) {
	srv := seededBank()
	defer srv.Close()

	// Fire K concurrent GETs and classify each, then apply the production verdict.
	raceOne := func(path string, k int) bool {
		outcomes := make([]txnOutcome, k)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < k; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				s, b := getReq(srv, path, tokA)
				outcomes[i] = classifyTxn(s, b)
			}(i)
		}
		close(start)
		wg.Wait()
		_, violation := raceVerdict(outcomes, 1)
		return violation
	}

	tp, fp, tn, fn := 0, 0, 0, 0
	if raceOne("/redeem/insecure", 20) {
		tp = 1
	} else {
		fn = 1
		t.Error("FALSE NEGATIVE: /redeem/insecure allows concurrent double-redeem but was not detected")
	}
	if raceOne("/redeem/secure", 20) {
		fp = 1
		t.Error("FALSE POSITIVE: /redeem/secure serializes redemption but was flagged")
	} else {
		tn = 1
	}
	reportMetrics(t, "race-condition", tp, fp, tn, fn)
}

func TestEvalSharedResourceException(t *testing.T) {
	srv := seededBank()
	defer srv.Close()

	// A legitimately-shared authenticated endpoint returns identical data to every
	// principal, so the raw differential classifies it as disclosure (a FP).
	os, ob := getReq(srv, "/announcements", tokA)
	cs, cb := getReq(srv, "/announcements", tokB)
	raw, _, _, _ := classifyAccess(os, cs, ob, cb, resourceIDs("GET /announcements HTTP/1.1"))
	if raw != authzVulnerable {
		t.Fatalf("precondition: expected raw differential to flag the shared endpoint, got %q", raw)
	}

	// With a configured expectation, the engine must downgrade expected access.
	exps := []authzExpectation{{Method: "GET", Pattern: "/announcements", SharedWith: []string{"authenticated"}}}
	cand := []authzCandidate{{Principal: "role:b", Verdict: raw}}
	if !matchExpectation(exps, "GET", "/announcements", "role:b") {
		t.Fatal("expectation should match the shared endpoint for an authenticated role")
	}
	for i := range cand {
		if cand[i].Verdict == authzVulnerable && matchExpectation(exps, "GET", "/announcements", cand[i].Principal) {
			cand[i].Verdict = authzNotVulnerable
		}
	}
	if cand[0].Verdict != authzNotVulnerable {
		t.Errorf("shared-resource FALSE POSITIVE not suppressed by expectation: %q", cand[0].Verdict)
	}

	// The exception must stay narrow: an unauthenticated principal is NOT covered by
	// "authenticated", and a genuinely private endpoint is still flagged.
	if matchExpectation(exps, "GET", "/announcements", "unauthenticated") {
		t.Error("'authenticated' must not cover the unauthenticated principal")
	}
	if matchExpectation(exps, "GET", "/accounts/{id}", "role:b") {
		t.Error("expectation must not leak to other endpoints")
	}
	t.Log("shared-resource exception: raw differential FP suppressed for declared principal; private endpoints and unauth still flagged")
}

func TestEvalBusinessLogicGroundTruth(t *testing.T) {
	srv := seededBank()
	defer srv.Close()
	inv := FinancialInvariants{AmountField: "amount", MaxAmount: 10000, CurrencyField: "currency", AllowedCurrencies: []string{"USD", "EUR"}, IdempotencyField: "idem"}
	base := `{"to":"200","amount":100,"currency":"USD","idem":"k1"}`

	// Run the amount-tamper + currency + replay experiments against both endpoints,
	// using the production deciders. Ground truth: /transfer is vulnerable, /transfer-secure is not.
	eval := func(path string) (violations int) {
		// amount negative / over-limit
		for _, tv := range amountTestValues(inv) {
			nb, _ := setJSONField(base, "amount", tv.raw)
			st, rb := postReq(srv, path, nb)
			if classifyTxn(st, rb) == txnAccepted && amountViolation(tv.val, inv) != "" {
				violations++
			}
		}
		// disallowed currency
		nb, _ := setJSONField(base, "currency", `"XTS"`)
		if st, rb := postReq(srv, path, nb); classifyTxn(st, rb) == txnAccepted {
			violations++
		}
		// replay / idempotency
		s1, b1 := postReq(srv, path, base)
		s2, b2 := postReq(srv, path, base)
		if classifyTxn(s1, b1) == txnAccepted && classifyTxn(s2, b2) == txnAccepted && !indicatesDuplicateSuppressed(b2) {
			violations++
		}
		return
	}

	vulnV := eval("/transfer")
	secureV := eval("/transfer-secure")

	tp, fp, tn, fn := 0, 0, 0, 0
	if vulnV > 0 {
		tp = 1
	} else {
		fn = 1
		t.Errorf("FALSE NEGATIVE: /transfer flagged no violations")
	}
	if secureV > 0 {
		fp = 1
		t.Errorf("FALSE POSITIVE: /transfer-secure flagged %d violations", secureV)
	} else {
		tn = 1
	}
	t.Logf("business-logic: /transfer violations=%d (expected >0), /transfer-secure violations=%d (expected 0)", vulnV, secureV)
	reportMetrics(t, "business-logic", tp, fp, tn, fn)
}

func TestEvalEndpointNormalizationCoverage(t *testing.T) {
	// Observed concrete paths -> expected unique normalized endpoints (ground truth).
	observed := []string{
		"/accounts/100", "/accounts/200", "/accounts/300", // -> 1 template
		"/statements/100", "/statements/200", // -> 1 template
		"/profile",                                               // -> 1
		"/orders/9f8e7d6c5b4a/items", "/orders/1122334455/items", // -> 1 template
	}
	want := map[string]bool{
		"/accounts/{id}":     true,
		"/statements/{id}":   true,
		"/profile":           true,
		"/orders/{id}/items": true,
	}
	got := map[string]bool{}
	for _, p := range observed {
		tmpl, _ := normalizePath(p)
		got[tmpl] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("normalization MISSED expected endpoint %q (got %v)", w, keys(got))
		}
	}
	coverage := 0
	for g := range got {
		if want[g] {
			coverage++
		}
	}
	t.Logf("endpoint normalization: %d/%d observed concrete paths collapsed to %d templates; coverage of %d ground-truth endpoints = %d",
		len(observed), len(observed), len(got), len(want), coverage)
	if len(got) != len(want) {
		t.Errorf("endpoint count = %d, want %d (%v)", len(got), len(want), keys(got))
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func reportMetrics(t *testing.T, label string, tp, fp, tn, fn int) {
	precision, recall, fpRate := 1.0, 1.0, 0.0
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn)
	}
	if fp+tn > 0 {
		fpRate = float64(fp) / float64(fp+tn)
	}
	t.Logf("[%s] TP=%d FP=%d TN=%d FN=%d | precision=%.2f recall=%.2f fp_rate=%.2f",
		label, tp, fp, tn, fn, precision, recall, fpRate)
}
