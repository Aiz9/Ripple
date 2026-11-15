package agent

import "testing"

func TestRawKind(t *testing.T) {
	cases := map[string]string{`"x"`: "string", `12`: "number", `true`: "bool", `[1]`: "array", `{"a":1}`: "object", `null`: "null"}
	for in, want := range cases {
		if got := rawKind(in); got != want {
			t.Errorf("rawKind(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBodyMutations(t *testing.T) {
	muts := bodyMutations(`{"amount":100,"note":"hi"}`)
	// per field: typeflip + null + removed (+ oversized for strings).
	kinds := map[string]map[string]bool{}
	for _, m := range muts {
		if kinds[m.Field] == nil {
			kinds[m.Field] = map[string]bool{}
		}
		kinds[m.Field][m.Kind] = true
	}
	if !kinds["amount"]["number→string"] || !kinds["amount"]["null"] || !kinds["amount"]["removed"] {
		t.Errorf("amount mutations incomplete: %v", kinds["amount"])
	}
	if !kinds["note"]["string→number"] || !kinds["note"]["oversized"] || !kinds["note"]["removed"] {
		t.Errorf("note mutations incomplete: %v", kinds["note"])
	}
	// each mutation body must be valid JSON-ish (non-empty, contains a brace)
	for _, m := range muts {
		if m.body == "" || m.body[0] != '{' {
			t.Errorf("bad mutation body for %s/%s: %q", m.Field, m.Kind, m.body)
		}
	}
	// non-JSON body -> no mutations
	if len(bodyMutations("not json")) != 0 {
		t.Error("expected no mutations for non-JSON body")
	}
}

func TestIsServerError(t *testing.T) {
	if !isServerError(500) || !isServerError(503) {
		t.Error("5xx should be server error")
	}
	if isServerError(400) || isServerError(200) {
		t.Error("non-5xx must not be server error")
	}
}
