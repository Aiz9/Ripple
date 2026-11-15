package server

import "testing"

// normalizeTaskID is id-agnostic: it strips the decorations the model adds and
// returns whatever id was inside, for ANY task number (not just the sample 772).
func TestNormalizeTaskID(t *testing.T) {
	cases := map[string]string{
		"task_772":   "772",
		"task: #772": "772",
		"Task #772":  "772",
		"#772":       "772",
		"  772 ":     "772",
		"772":        "772",
		// Arbitrary other ids resolve the same way — nothing is pinned to 772.
		"task_1":     "1",
		"task: #42":  "42",
		"#1000000":   "1000000",
		"task 58392": "58392",
	}
	for in, want := range cases {
		if got := normalizeTaskID(in); got != want {
			t.Errorf("normalizeTaskID(%q) = %q, want %q", in, got, want)
		}
	}
}
