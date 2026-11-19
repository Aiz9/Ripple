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

func mutationKinds(muts []mutation) map[string]map[string]bool {
	kinds := map[string]map[string]bool{}
	for _, m := range muts {
		if kinds[m.Field] == nil {
			kinds[m.Field] = map[string]bool{}
		}
		kinds[m.Field][m.Kind] = true
	}
	return kinds
}

func TestRequestMutationsJSON(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"amount\":100,\"note\":\"hi\"}"
	muts := requestMutations(raw)
	kinds := mutationKinds(muts)
	if !kinds["amount"]["number→string"] || !kinds["amount"]["null"] || !kinds["amount"]["removed"] {
		t.Errorf("amount mutations incomplete: %v", kinds["amount"])
	}
	if !kinds["note"]["string→number"] || !kinds["note"]["oversized"] || !kinds["note"]["removed"] {
		t.Errorf("note mutations incomplete: %v", kinds["note"])
	}
	for _, m := range muts {
		if m.req == "" || !contains(m.req, "POST /x HTTP/1.1") {
			t.Errorf("mutation not a full request for %s/%s", m.Field, m.Kind)
		}
	}
	// no body -> no mutations
	if len(requestMutations("GET /x HTTP/1.1\r\nHost: h\r\n\r\n")) != 0 {
		t.Error("expected no mutations for a request with no body")
	}
}

func TestRequestMutationsForm(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\namount=100&note=hi"
	muts := requestMutations(raw)
	kinds := mutationKinds(muts)
	if len(kinds) != 2 {
		t.Fatalf("expected amount+note fields, got %v", kinds)
	}
	if !kinds["amount"]["removed"] || !kinds["amount"]["oversized"] {
		t.Errorf("form amount mutations incomplete: %v", kinds["amount"])
	}
	for _, m := range muts {
		if !contains(m.req, "amount=") && m.Kind != "removed" {
			continue
		}
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
