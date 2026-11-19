package agent

import "testing"

func TestLooksGraphQL(t *testing.T) {
	q := "POST /api HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"query\":\"{me{id}}\"}"
	if !looksGraphQL(q) {
		t.Error("query body should be graphql")
	}
	if !looksGraphQL("POST /graphql HTTP/1.1\r\nHost: h\r\n\r\n") {
		t.Error("graphql path should match")
	}
	if looksGraphQL("GET /accounts HTTP/1.1\r\nHost: h\r\n\r\n") {
		t.Error("plain REST must not match")
	}
}

func TestIntrospectionEnabled(t *testing.T) {
	ok := `{"data":{"__schema":{"types":[{"name":"Query"}]}}}`
	if !introspectionEnabled(200, ok) {
		t.Error("schema with types should be detected")
	}
	// disabled -> error response, no schema
	if introspectionEnabled(400, `{"errors":[{"message":"introspection disabled"}]}`) {
		t.Error("error response must not be detected as enabled")
	}
	if introspectionEnabled(200, `{"data":{"me":{"id":1}}}`) {
		t.Error("normal data response must not be introspection")
	}
}
