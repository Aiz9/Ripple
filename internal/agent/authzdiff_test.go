package agent

import "testing"

func resp(status, body string) string {
	return "HTTP/1.1 " + status + "\r\nContent-Type: application/json\r\n\r\n" + body
}

func TestHTTPStatusAndBody(t *testing.T) {
	r := resp("200 OK", `{"a":1}`)
	if got := httpStatus(r); got != 200 {
		t.Fatalf("status = %d, want 200", got)
	}
	if got := httpBody(r); got != `{"a":1}` {
		t.Fatalf("body = %q", got)
	}
	if httpStatus("garbage") != 0 {
		t.Fatalf("expected 0 status for garbage")
	}
}

func TestResourceIDs(t *testing.T) {
	req := "GET /api/v1/accounts/100345/balance?beneficiary=5f2b9c1a4d8e HTTP/1.1\r\nHost: x\r\n\r\n"
	ids := resourceIDs(req)
	want := map[string]bool{"100345": true, "5f2b9c1a4d8e": true}
	for _, id := range ids {
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatalf("resourceIDs missed %v (got %v)", want, ids)
	}
	// "v1", "balance", "accounts", "api" must not be treated as IDs.
	for _, id := range ids {
		if id == "balance" || id == "accounts" || id == "api" {
			t.Fatalf("non-id token %q classified as id", id)
		}
	}
}

func TestClassifyAccess(t *testing.T) {
	ownerBody := `{"account":"100345","owner":"alice","balance":4200}`
	ids := []string{"100345"}

	tests := []struct {
		name                    string
		ownerStatus, candStatus int
		candBody                string
		want                    string
	}{
		{"denied-403", 200, 403, `{"error":"forbidden"}`, authzNotVulnerable},
		{"denied-401", 200, 401, ``, authzNotVulnerable},
		{"notfound-404", 200, 404, `{"error":"not found"}`, authzNotVulnerable},
		{"disclosure-identical", 200, 200, ownerBody, authzVulnerable},
		{"disclosure-shared-id", 200, 200, `{"ref":"100345","data":"different shape entirely here yes"}`, authzVulnerable},
		{"inconclusive-own-data", 200, 200, `{"account":"999999","owner":"bob","balance":10}`, authzInconclusive},
		{"inconclusive-empty", 200, 200, ``, authzInconclusive},
		{"no-baseline", 403, 200, ownerBody, authzNoBaseline},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, reason, _, _ := classifyAccess(tt.ownerStatus, tt.candStatus, ownerBody, tt.candBody, ids)
			if v != tt.want {
				t.Fatalf("verdict = %q (%s), want %q", v, reason, tt.want)
			}
		})
	}
}

func TestStripAuthHeaders(t *testing.T) {
	raw := "GET /me HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer abc\r\nCookie: s=1\r\nAccept: */*\r\n\r\n"
	out := stripAuthHeaders(raw)
	if contains(out, "Authorization") || contains(out, "Cookie:") {
		t.Fatalf("auth headers not stripped: %q", out)
	}
	if !contains(out, "Accept: */*") || !contains(out, "GET /me HTTP/1.1") {
		t.Fatalf("non-auth content lost: %q", out)
	}
}

func TestAuthzFindingBlock(t *testing.T) {
	// No confirmed candidate -> no finding.
	if authzFindingBlock("GET", "h", "/a", []authzCandidate{{Principal: "role:b", Verdict: authzInconclusive}}) != nil {
		t.Fatal("inconclusive must not produce a finding")
	}
	// A vulnerable candidate -> confirmed finding block.
	fb := authzFindingBlock("GET", "h", "/accounts/{id}", []authzCandidate{
		{Principal: "role:b", Verdict: authzVulnerable, Status: 200},
		{Principal: "unauthenticated", Verdict: authzNotVulnerable, Status: 401},
	})
	if fb == nil || fb.VerificationStatus != "confirmed" {
		t.Fatalf("expected confirmed finding, got %v", fb)
	}
	if fb.Severity != "high" || fb.VulnClass == "" {
		t.Fatalf("finding missing fields: %+v", fb)
	}
	ev := fb.evidenceMarkdown()
	for _, want := range []string{"Reproduction", "Expected behaviour", "Actual behaviour", "Remediation", "Affected endpoint"} {
		if !contains(ev, want) {
			t.Errorf("evidence markdown missing %q section:\n%s", want, ev)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
