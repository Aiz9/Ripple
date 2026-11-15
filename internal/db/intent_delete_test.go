package db

import "testing"

// mustIntent / mustNode / mustLink are terse builders for the delete-cascade tests.
func mustIntent(t *testing.T, es *ExplorationStore, summary string) int64 {
	t.Helper()
	id, err := es.AddIntent(map[string]any{"summary": summary}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustNode(t *testing.T, es *ExplorationStore, kind, summary string) int64 {
	t.Helper()
	id, err := es.AddNode(kind, map[string]any{"summary": summary}, 1, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustLink(t *testing.T, es *ExplorationStore, from int64, rel string, to int64) {
	t.Helper()
	if err := es.Link(from, rel, to); err != nil {
		t.Fatal(err)
	}
}

func gone(t *testing.T, es *ExplorationStore, id int64) bool {
	t.Helper()
	n, err := es.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	return n == nil
}

// TestSoftDeleteIntent sets deleted/delete_reason while retaining the node.
func TestSoftDeleteIntent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("soft delete", "\u5047\u5220\u9664")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	intent := mustIntent(t, es, "\u5f85\u5220\u610f\u56fe")
	if err := es.SetIntentState(intent, "paused"); err != nil {
		t.Fatal(err)
	}
	summary, err := es.SoftDeleteIntent(intent, "\u65b9\u5411\u5224\u65ad\u9519\u8bef")
	if err != nil {
		t.Fatal(err)
	}
	if summary != "\u5f85\u5220\u610f\u56fe" {
		t.Fatalf("summary=%q, want \u5f85\u5220\u610f\u56fe", summary)
	}
	n, err := es.GetNode(intent)
	if err != nil || n == nil {
		t.Fatalf("intent removed by soft delete: n=%+v err=%v", n, err)
	}
	if n.State != StateIntentDeleted || n.DeleteReason != "\u65b9\u5411\u5224\u65ad\u9519\u8bef" {
		t.Fatalf("state=%q delete_reason=%q, want deleted/\u65b9\u5411\u5224\u65ad\u9519\u8bef", n.State, n.DeleteReason)
	}
	// Open pending intents may also be soft-deleted.
	openIntent := mustIntent(t, es, "\u5f85\u9886\u610f\u56fe")
	if _, err := es.SoftDeleteIntent(openIntent, "\u65b9\u5411\u4e0d\u9700\u8981\u4e86"); err != nil {
		t.Fatalf("soft delete open intent: %v", err)
	}
	if n, err := es.GetNode(openIntent); err != nil || n == nil || n.State != StateIntentDeleted {
		t.Fatalf("open intent not soft-deleted: n=%+v err=%v", n, err)
	}

	// Already-deleted and other unsupported states cannot be soft-deleted again.
	if _, err := es.SoftDeleteIntent(intent, "\u518d\u5220"); err == nil {
		t.Fatal("soft-deleting an already-deleted intent unexpectedly succeeded")
	}
}

// TestHardDeleteCascadesExclusiveDescendants cascades exclusive descendants through leaves.
func TestHardDeleteCascadesExclusiveDescendants(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("hard cascade", "\u7ea7\u8054\u5220\u9664")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	// intent1 --yields--> fact1 --derived_from--> intent2 --yields--> fact2 (leaf).
	intent1 := mustIntent(t, es, "\u6839\u610f\u56fe")
	fact1 := mustNode(t, es, KindFact, "\u4e8b\u5b9e1")
	mustLink(t, es, intent1, RelYields, fact1)
	intent2 := mustIntent(t, es, "\u884d\u751f\u610f\u56fe")
	mustLink(t, es, fact1, RelDerivedFrom, intent2)
	fact2 := mustNode(t, es, KindFact, "\u4e8b\u5b9e2")
	mustLink(t, es, intent2, RelYields, fact2)

	cleanup, err := es.CancelIntent(intent1)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.Intents != 2 || cleanup.Facts != 2 {
		t.Fatalf("cleanup=%+v, want 2 intents / 2 facts", cleanup)
	}
	for _, id := range []int64{intent1, fact1, intent2, fact2} {
		if !gone(t, es, id) {
			t.Fatalf("node %d survived cascade", id)
		}
	}
}

// TestHardDeletePreservesSharedAndGoal retains shared descendants and goals.
func TestHardDeletePreservesSharedAndGoal(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("hard preserve", "\u4fdd\u7559\u5171\u4eab/\u76ee\u6807")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	goal, err := es.AddGoal(map[string]any{"text": "\u62ff\u4e0b\u540e\u53f0"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	// intent1 exclusively supports a finding proving a goal; intent1/intentX share fact1 -> intent2.
	intent1 := mustIntent(t, es, "\u5f85\u5220\u610f\u56fe")
	intentX := mustIntent(t, es, "\u65c1\u8def\u610f\u56fe")
	finding := mustNode(t, es, KindFinding, "\u6f0f\u6d1e")
	mustLink(t, es, intent1, RelYields, finding)
	mustLink(t, es, finding, RelProves, goal)
	shared := mustNode(t, es, KindFact, "\u5171\u4eab\u4e8b\u5b9e")
	mustLink(t, es, intent1, RelYields, shared)
	mustLink(t, es, intentX, RelYields, shared)
	intent2 := mustIntent(t, es, "\u7531\u5171\u4eab\u4e8b\u5b9e\u884d\u751f")
	mustLink(t, es, shared, RelDerivedFrom, intent2)

	cleanup, err := es.CancelIntent(intent1)
	if err != nil {
		t.Fatal(err)
	}
	// Delete intent1 and exclusive finding; preserve shared fact1, intent2, and goal.
	if cleanup.Intents != 1 || cleanup.Findings != 1 || cleanup.Facts != 0 {
		t.Fatalf("cleanup=%+v, want 1 intent / 1 finding / 0 fact", cleanup)
	}
	if !gone(t, es, intent1) || !gone(t, es, finding) {
		t.Fatal("intent1/finding should be removed")
	}
	for _, id := range []int64{goal, intentX, shared, intent2} {
		if gone(t, es, id) {
			t.Fatalf("node %d was wrongly cascaded", id)
		}
	}
}
