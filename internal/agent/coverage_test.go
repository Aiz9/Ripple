package agent

import "testing"

func TestCoverageLedger(t *testing.T) {
	const task = 77123
	recordCoverage(task, "GET /accounts/{id}", "authz")
	recordCoverage(task, "GET /accounts/{id}", "injection")
	recordCoverage(task, "POST /transfers", "business-logic")
	recordCoverage(task, "", "x")      // ignored
	recordCoverage(task, "GET /x", "") // ignored
	snap := coverageSnapshot(task)
	if len(snap) != 2 {
		t.Fatalf("expected 2 endpoints, got %d: %v", len(snap), snap)
	}
	got := map[string]bool{}
	for _, c := range snap["GET /accounts/{id}"] {
		got[c] = true
	}
	if !got["authz"] || !got["injection"] {
		t.Errorf("checks not recorded: %v", snap["GET /accounts/{id}"])
	}
}

func TestPathFromURL(t *testing.T) {
	cases := map[string]string{
		"https://h/accounts/{id}/balance": "/accounts/{id}/balance",
		"https://h/login?x=1":             "/login",
		"http://h":                        "/",
	}
	for in, want := range cases {
		if got := pathFromURL(in); got != want {
			t.Errorf("pathFromURL(%q)=%q want %q", in, got, want)
		}
	}
}
