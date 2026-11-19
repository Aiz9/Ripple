package agent

import "testing"

func TestBodyFormat(t *testing.T) {
	json := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
	form := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1&b=2"
	mp := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=xyz\r\n\r\n--xyz"
	none := "GET /x HTTP/1.1\r\nHost: h\r\n\r\n"
	for raw, want := range map[string]string{json: "json", form: "form", mp: "multipart", none: "none"} {
		if got := bodyFormat(raw); got != want {
			t.Errorf("bodyFormat=%q want %q", got, want)
		}
	}
	// sniff without content-type
	if bodyFormat("POST /x HTTP/1.1\r\nHost: h\r\n\r\n{\"a\":1}") != "json" {
		t.Error("should sniff json")
	}
	if bodyFormat("POST /x HTTP/1.1\r\nHost: h\r\n\r\na=1&b=2") != "form" {
		t.Error("should sniff form")
	}
}

func TestFormFieldOps(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\namount=100&to=B"
	_, fields := bodyFieldTypes(raw)
	if fields["amount"] != "integer" || fields["to"] != "string" {
		t.Fatalf("form field types wrong: %v", fields)
	}
	// set existing
	out, ok := setBodyFieldRaw(raw, "amount", "-1")
	if !ok || !contains(out, "amount=-1") {
		t.Fatalf("setBodyFieldRaw form failed: %q", httpBody(out))
	}
	// string injection
	out2, ok := setBodyFieldString(raw, "to", "x' OR '1'='1")
	if !ok || !contains(httpBody(out2), "to=") {
		t.Fatalf("setBodyFieldString form failed: %q", httpBody(out2))
	}
	// add absent field (mass assignment)
	out3, ok := addBodyFieldRaw(raw, "role", `"admin"`)
	if !ok || !contains(httpBody(out3), "role=admin") {
		t.Fatalf("addBodyFieldRaw form failed: %q", httpBody(out3))
	}
	// remove
	out4, ok := removeBodyField(raw, "to")
	if !ok || contains(httpBody(out4), "to=") {
		t.Fatalf("removeBodyField form failed: %q", httpBody(out4))
	}
}

func TestJSONFieldOpsViaCodec(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"amount\":100,\"to\":\"B\"}"
	out, ok := setBodyFieldRaw(raw, "amount", "-1")
	if !ok {
		t.Fatal("json setBodyFieldRaw failed")
	}
	if n, _ := jsonNumber(httpBody(out), "amount"); n != -1 {
		t.Errorf("amount not set: %q", httpBody(out))
	}
	out2, _ := addBodyFieldRaw(raw, "is_admin", "true")
	if !reflectsInjected(httpBody(out2), "is_admin", "true") {
		t.Errorf("json add failed: %q", httpBody(out2))
	}
}
