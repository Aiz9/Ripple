package agent

import "testing"

func TestBalanceVerdict(t *testing.T) {
	// accepted, debit matches -> consistent
	if ok, iss := balanceVerdict(txnAccepted, 1000, 900, 100); !ok || iss != "" {
		t.Errorf("exact debit should be consistent, got %v %q", ok, iss)
	}
	// accepted, no change -> inconsistent (no debit)
	if ok, _ := balanceVerdict(txnAccepted, 1000, 1000, 100); ok {
		t.Error("accepted transfer with no debit must be flagged")
	}
	// accepted, wrong debit -> inconsistent
	if ok, _ := balanceVerdict(txnAccepted, 1000, 950, 100); ok {
		t.Error("debit != amount must be flagged")
	}
	// rejected, no change -> consistent
	if ok, iss := balanceVerdict(txnRejected, 1000, 1000, 100); !ok || iss != "" {
		t.Errorf("rejected with no effect should be consistent, got %v %q", ok, iss)
	}
	// rejected, balance changed -> inconsistent (failed txn had effect)
	if ok, _ := balanceVerdict(txnRejected, 1000, 900, 100); ok {
		t.Error("rejected txn that changed balance must be flagged")
	}
	// error -> not flagged
	if ok, _ := balanceVerdict(txnError, 1000, 500, 100); !ok {
		t.Error("error outcome must not be flagged")
	}
}
