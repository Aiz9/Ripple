package agent

import "testing"

func TestRateLimited(t *testing.T) {
	if !rateLimited([]int{200, 200, 429}, []string{"", "", ""}) {
		t.Error("429 should count as throttled")
	}
	if !rateLimited([]int{200, 200}, []string{"", "Too many attempts, try again later"}) {
		t.Error("lockout message should count as throttled")
	}
	if rateLimited([]int{401, 401, 401, 401}, []string{"bad creds", "bad creds", "", ""}) {
		t.Error("repeated 401 with no throttle must NOT be throttled")
	}
	if rateLimited([]int{200, 200, 200}, []string{"", "", ""}) {
		t.Error("all-200 with no markers must not be throttled")
	}
}
