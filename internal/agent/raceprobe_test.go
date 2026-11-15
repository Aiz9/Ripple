package agent

import "testing"

func TestRaceVerdict(t *testing.T) {
	acc := []txnOutcome{txnAccepted, txnAccepted, txnRejected, txnError, txnAccepted}
	n, viol := raceVerdict(acc, 1)
	if n != 3 || !viol {
		t.Fatalf("accepted=%d violation=%v, want 3,true", n, viol)
	}
	// within the allowed limit -> no violation
	if _, viol := raceVerdict([]txnOutcome{txnAccepted, txnRejected, txnRejected}, 1); viol {
		t.Error("single acceptance must not be a violation at expectedMax=1")
	}
	// expectedMax respected
	if _, viol := raceVerdict([]txnOutcome{txnAccepted, txnAccepted, txnAccepted}, 3); viol {
		t.Error("3 accepted with expectedMax=3 must not be a violation")
	}
	if _, viol := raceVerdict([]txnOutcome{txnAccepted, txnAccepted, txnAccepted, txnAccepted}, 3); !viol {
		t.Error("4 accepted with expectedMax=3 must be a violation")
	}
	// expectedMax<1 is clamped to 1
	if _, viol := raceVerdict([]txnOutcome{txnAccepted, txnAccepted}, 0); !viol {
		t.Error("expectedMax<1 should clamp to 1 -> 2 accepted is a violation")
	}
}
