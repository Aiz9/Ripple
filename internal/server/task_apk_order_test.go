package server

import (
	"regexp"
	"strconv"
	"testing"
)

// phaseOrder extracts the catalog section number from each seeded phase goal, in
// emission order.
func phaseOrder(t *testing.T) []int {
	t.Helper()
	re := regexp.MustCompile(`Phase (\d{2}) `)
	var order []int
	for _, g := range apkPhaseGoals() {
		m := re.FindStringSubmatch(g.Text)
		if m == nil {
			t.Fatalf("goal has no phase header: %q", g.Text)
		}
		n, _ := strconv.Atoi(m[1])
		order = append(order, n)
	}
	return order
}

func TestAPKPhaseGoalsAreRuntimeFirst(t *testing.T) {
	order := phaseOrder(t)
	pos := map[int]int{}
	for i, s := range order {
		pos[s] = i
	}
	// Dynamic setup (04) and runtime API testing (05) must precede the static
	// support phases (02 information gathering, 03 static analysis).
	for _, runtime := range []int{4, 5, 6, 7} {
		for _, static := range []int{2, 3} {
			if pos[runtime] >= pos[static] {
				t.Fatalf("runtime phase %02d should come before static phase %02d (order=%v)", runtime, static, order)
			}
		}
	}
	// Scoping leads, reporting is last.
	if order[0] != 1 {
		t.Fatalf("expected phase 01 (scoping) first, got %02d", order[0])
	}
	if order[len(order)-1] != 13 {
		t.Fatalf("expected phase 13 (reporting) last, got %02d", order[len(order)-1])
	}
}
