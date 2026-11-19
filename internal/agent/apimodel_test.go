package agent

import "testing"

func TestInferJSONType(t *testing.T) {
	cases := map[string]string{
		`"x"`: "string", `42`: "integer", `4.2`: "number", `-7`: "integer",
		`true`: "boolean", `[1]`: "array", `{"a":1}`: "object", `null`: "null",
		`1e3`: "number",
	}
	for in, want := range cases {
		if got := inferJSONType(in); got != want {
			t.Errorf("inferJSONType(%q)=%q want %q", in, got, want)
		}
	}
}

func TestInferStringType(t *testing.T) {
	cases := map[string]string{"100": "integer", "3.14": "number", "true": "boolean", "hello": "string", "": "string"}
	for in, want := range cases {
		if got := inferStringType(in); got != want {
			t.Errorf("inferStringType(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAPIVersion(t *testing.T) {
	cases := map[string]string{
		"/api/v2/accounts/{id}": "v2",
		"/v1/login":             "v1",
		"/accounts/{id}":        "",
		"/v10/x":                "v10",
		"/service/v2.1/x":       "v2.1",
	}
	for in, want := range cases {
		if got := apiVersion(in); got != want {
			t.Errorf("apiVersion(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEndpointConfidence(t *testing.T) {
	if c, _ := endpointConfidence("observed", 5); c < 0.9 {
		t.Errorf("strong observed should be >=0.9, got %v", c)
	}
	if c, _ := endpointConfidence("observed", 1); c > 0.7 {
		t.Errorf("single observed should be modest, got %v", c)
	}
	if _, tier := endpointConfidence("spec", 0); tier != "inferred" {
		t.Errorf("spec should be inferred tier, got %q", tier)
	}
}

func TestOwnershipMap(t *testing.T) {
	const task = 55221
	setIdentity(task, Identity{Role: "user_a", Headers: map[string]string{"Authorization": "A"}, Owns: []string{"100", "ben1"}})
	setIdentity(task, Identity{Role: "user_b", Headers: map[string]string{"Authorization": "B"}, Owns: []string{"200"}})
	m := ownershipMap(task)
	if len(m["user_a"]) != 2 || m["user_b"][0] != "200" {
		t.Fatalf("ownership map wrong: %v", m)
	}
	if ownerOfID(task, "100") != "user_a" || ownerOfID(task, "200") != "user_b" {
		t.Error("ownerOfID lookup failed")
	}
	if ownerOfID(task, "999") != "" {
		t.Error("unknown id should have no owner")
	}
}

func TestMergeTypeAndSchemas(t *testing.T) {
	if mergeType("", "integer") != "integer" {
		t.Error("first observation should set type")
	}
	if mergeType("integer", "integer") != "integer" {
		t.Error("same type should stay")
	}
	if mergeType("integer", "string") != "mixed" {
		t.Error("conflicting types should be mixed")
	}
	pt := topLevelTypes(`{"amount":100,"note":"x","ok":true}`)
	if pt["amount"] != "integer" || pt["note"] != "string" || pt["ok"] != "boolean" {
		t.Errorf("response schema types wrong: %v", pt)
	}
	qt := queryParamTypes("GET /x?page=2&q=hello HTTP/1.1\r\nHost: h\r\n\r\n")
	if qt["page"] != "integer" || qt["q"] != "string" {
		t.Errorf("query types wrong: %v", qt)
	}
}
