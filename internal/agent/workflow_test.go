package agent

import "testing"

func TestClassifyStep(t *testing.T) {
	steps := []workflowStep{
		{State: "initiate", Method: "POST", Pattern: "/transfers"},
		{State: "verify", Method: "POST", Pattern: "/transfers/{id}/otp"},
		{State: "confirm", Method: "POST", Pattern: "/transfers/{id}/confirm"},
	}
	if s, ok := classifyStep(steps, "POST", "/transfers/{id}/confirm"); !ok || s != "confirm" {
		t.Fatalf("confirm classify = %q,%v", s, ok)
	}
	if s, ok := classifyStep(steps, "GET", "/transfers/{id}/confirm"); ok {
		t.Fatalf("method mismatch should not classify, got %q", s)
	}
	if _, ok := classifyStep(steps, "POST", "/unrelated"); ok {
		t.Fatal("unrelated path should not classify")
	}
}

func TestFieldValue(t *testing.T) {
	q := "POST /x?transaction_id=T99 HTTP/1.1\r\nHost: h\r\n\r\n"
	if v := fieldValue(q, "transaction_id"); v != "T99" {
		t.Fatalf("query field = %q", v)
	}
	b := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"transaction_id\":\"T42\",\"amount\":10}"
	if v := fieldValue(b, "transaction_id"); v != "T42" {
		t.Fatalf("body field = %q", v)
	}
	if v := fieldValue(b, "missing"); v != "" {
		t.Fatalf("absent field should be empty, got %q", v)
	}
}

func TestSeqViolations(t *testing.T) {
	order := stateIndex([]string{"initiate", "verify", "confirm"})
	// in-order: no violation
	if v := seqViolations(order, []string{"initiate", "verify", "confirm"}); len(v) != 0 {
		t.Fatalf("in-order flagged: %v", v)
	}
	// skip verify: initiate -> confirm is a forward skip
	if v := seqViolations(order, []string{"initiate", "confirm"}); len(v) != 1 {
		t.Fatalf("skip not detected: %v", v)
	}
	// straight to confirm (only confirm observed): no pair to compare -> no violation
	if v := seqViolations(order, []string{"confirm"}); len(v) != 0 {
		t.Fatalf("single step flagged: %v", v)
	}
	// backward/retry: not flagged
	if v := seqViolations(order, []string{"verify", "initiate"}); len(v) != 0 {
		t.Fatalf("backward transition flagged: %v", v)
	}
}
