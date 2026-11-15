package mobiletest

import "testing"

func TestFlowIsOrderedAndCoversWholeCatalog(t *testing.T) {
	phases := Flow()
	if len(phases) == 0 {
		t.Fatal("flow has no phases")
	}
	total := 0
	prev := 0
	for _, p := range phases {
		if p.Index <= prev {
			t.Fatalf("phases not strictly ordered: %d after %d (%q)", p.Index, prev, p.Section)
		}
		prev = p.Index
		if len(p.Controls) == 0 {
			t.Fatalf("phase %q has no procedures", p.Section)
		}
		if p.Name == "" || p.Name == p.Section {
			t.Fatalf("phase %q did not strip its numeric prefix", p.Section)
		}
		if len(p.Objectives) == 0 {
			t.Fatalf("phase %q has no objectives", p.Section)
		}
		total += len(p.Controls)
	}
	if total != len(Catalog()) {
		t.Fatalf("flow covers %d procedures, catalog has %d", total, len(Catalog()))
	}
	// First phase is pre-engagement/scoping; signals/requires aggregation works.
	if phases[0].Index != 1 {
		t.Fatalf("first phase index = %d, want 1", phases[0].Index)
	}
}
