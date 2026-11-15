package agent

import "testing"

func TestDetectSSTI(t *testing.T) {
	if !detectSSTI(`result: 1022117 done`) {
		t.Error("evaluated product not detected")
	}
	if detectSSTI(`result: {{1009*1013}}`) {
		t.Error("literal (unevaluated) expression must not be detected")
	}
	if detectSSTI(`nothing here`) {
		t.Error("false positive on unrelated body")
	}
}

func TestDetectSQLError(t *testing.T) {
	positives := []string{
		`You have an error in your SQL syntax near`,
		`org.postgresql.util.PSQLException: ERROR`,
		`ORA-00933: SQL command not properly ended`,
		`Warning: mysql_fetch_array()`,
		`SQLSTATE[42000]`,
	}
	for _, p := range positives {
		if !detectSQLError(p) {
			t.Errorf("missed DB error: %q", p)
		}
	}
	if detectSQLError(`{"results":[],"ok":true}`) {
		t.Error("false positive on normal JSON")
	}
}

func TestInjectableTargets(t *testing.T) {
	raw := "POST /search?q=hello&page=1 HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"name\":\"bob\",\"count\":3}"
	tgts := injectableTargets(raw)
	got := map[string]bool{}
	for _, tg := range tgts {
		got[tg.Location+":"+tg.Name] = true
	}
	if !got["query:q"] || !got["query:page"] || !got["body:name"] {
		t.Errorf("missing expected targets: %v", got)
	}
	if got["body:count"] {
		t.Error("non-string body field should not be an injection target")
	}
}

func TestInjectInto(t *testing.T) {
	raw := "GET /s?q=x HTTP/1.1\r\nHost: h\r\n\r\n"
	out, ok := injectInto(raw, injectTarget{"query", "q"}, "{{1009*1013}}")
	if !ok || !contains(out, "q=") {
		t.Fatalf("query inject failed: %q", out)
	}
	rawB := "POST /s HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"name\":\"x\"}"
	outB, ok := injectInto(rawB, injectTarget{"body", "name"}, `'`)
	if !ok || httpBody(outB) == `{"name":"x"}` {
		t.Fatalf("body inject failed: %q", httpBody(outB))
	}
}
