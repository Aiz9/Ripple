package agent

import "testing"

func TestPrincipalAllowed(t *testing.T) {
	cases := []struct {
		shared    []string
		principal string
		want      bool
	}{
		{[]string{"public"}, "unauthenticated", true},
		{[]string{"public"}, "role:b", true},
		{[]string{"authenticated"}, "role:b", true},
		{[]string{"authenticated"}, "unauthenticated", false},
		{[]string{"unauthenticated"}, "unauthenticated", true},
		{[]string{"unauthenticated"}, "role:b", false},
		{[]string{"admin"}, "role:admin", true},
		{[]string{"admin"}, "role:b", false},
		{[]string{"admin", "manager"}, "role:manager", true},
	}
	for _, c := range cases {
		if got := principalAllowed(c.shared, c.principal); got != c.want {
			t.Errorf("principalAllowed(%v,%q) = %v want %v", c.shared, c.principal, got, c.want)
		}
	}
}

func TestMatchExpectation(t *testing.T) {
	exps := []authzExpectation{
		{Method: "GET", Pattern: "/announcements", SharedWith: []string{"authenticated"}},
		{Method: "", Pattern: "/shared/*", SharedWith: []string{"public"}},
		{Method: "GET", Pattern: "/admin/*", SharedWith: []string{"admin"}},
	}
	tests := []struct {
		method, path, principal string
		want                    bool
	}{
		{"GET", "/announcements", "role:b", true},
		{"POST", "/announcements", "role:b", false},          // method mismatch
		{"GET", "/announcements", "unauthenticated", false},  // principal not covered
		{"DELETE", "/shared/files", "unauthenticated", true}, // any method, public, glob
		{"GET", "/admin/report", "role:admin", true},
		{"GET", "/admin/report", "role:b", false},  // only admin
		{"GET", "/accounts/{id}", "role:b", false}, // no matching pattern
	}
	for _, tt := range tests {
		if got := matchExpectation(exps, tt.method, tt.path, tt.principal); got != tt.want {
			t.Errorf("matchExpectation(%s %s as %s) = %v want %v", tt.method, tt.path, tt.principal, got, tt.want)
		}
	}
}

func TestApplyAuthzExpectations(t *testing.T) {
	ts := &ToolSet{taskID: 9991}
	addAuthzExpectation(9991, authzExpectation{Method: "GET", Pattern: "/announcements", SharedWith: []string{"authenticated"}})
	cands := []authzCandidate{
		{Principal: "role:b", Verdict: authzVulnerable},
		{Principal: "unauthenticated", Verdict: authzVulnerable}, // not covered -> stays flagged
	}
	n := ts.applyAuthzExpectations("GET", "/announcements", cands)
	if n != 1 {
		t.Fatalf("downgraded %d, want 1", n)
	}
	if cands[0].Verdict != authzNotVulnerable {
		t.Errorf("authenticated role should be downgraded, got %q", cands[0].Verdict)
	}
	if cands[1].Verdict != authzVulnerable {
		t.Errorf("unauthenticated must stay flagged, got %q", cands[1].Verdict)
	}
}
