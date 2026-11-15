package server

import "testing"

func TestAPKMarkerAndPhaseGoals(t *testing.T) {
	if _, ok := apkMarkerID("no marker here"); ok {
		t.Fatal("false marker match")
	}
	id, ok := apkMarkerID("[Android APK: " + "a" + "]\nAndroid APK security assessment")
	// 'a' is not a valid apk id; should fail the pattern.
	if ok {
		t.Fatalf("invalid apk id accepted: %q", id)
	}
	// A plausible 64-hex sha should parse.
	sha := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	id, ok = apkMarkerID("[Android APK: " + sha + "]\nbody")
	if !ok || id != sha {
		t.Fatalf("valid marker not parsed: ok=%v id=%q", ok, id)
	}
	goals := apkPhaseGoals()
	if len(goals) != 13 {
		t.Fatalf("expected 13 phase goals, got %d", len(goals))
	}
	for i, g := range goals {
		if len(g.Text) < 20 {
			t.Fatalf("phase %d goal text too short: %q", i, g.Text)
		}
	}
}
