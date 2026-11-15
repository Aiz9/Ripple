package agent

import "testing"

func TestAddOrSetJSONField(t *testing.T) {
	// adds a field that was absent
	out, ok := addOrSetJSONField(`{"name":"x"}`, "role", `"admin"`)
	if !ok {
		t.Fatal("addOrSet failed")
	}
	if !bodyHasField(out, "role") {
		t.Fatalf("role not added: %q", out)
	}
	// replaces an existing one
	out2, _ := addOrSetJSONField(`{"role":"user"}`, "role", `"admin"`)
	if !reflectsInjected(out2, "role", `"admin"`) {
		t.Fatalf("role not replaced: %q", out2)
	}
}

func TestBodyHasField(t *testing.T) {
	if !bodyHasField(`{"Role":"user"}`, "role") {
		t.Error("case-insensitive field match failed")
	}
	if bodyHasField(`{"name":"x"}`, "role") {
		t.Error("absent field reported present")
	}
}

func TestReflectsInjected(t *testing.T) {
	// top-level reflection
	if !reflectsInjected(`{"id":1,"role":"admin"}`, "role", `"admin"`) {
		t.Error("top-level role=admin not detected")
	}
	// nested reflection, case-insensitive key, bool value
	if !reflectsInjected(`{"user":{"isAdmin":true}}`, "isAdmin", `true`) {
		t.Error("nested bool reflection not detected")
	}
	// value mismatch -> not reflected (server kept a different value)
	if reflectsInjected(`{"role":"user"}`, "role", `"admin"`) {
		t.Error("mismatched value wrongly treated as applied")
	}
	// field absent -> not reflected
	if reflectsInjected(`{"id":1}`, "role", `"admin"`) {
		t.Error("absent field wrongly treated as applied")
	}
	// non-JSON response -> not reflected
	if reflectsInjected(`forbidden`, "role", `"admin"`) {
		t.Error("non-JSON wrongly treated as applied")
	}
}
