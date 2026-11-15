package notify

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Lock down the capability boundary of generic Webhook templates.
//
// This is the only place user strings are evaluated as code; explicitly test available
// capabilities so an exported context method or readFile FuncMap addition cannot silently
// expand access while appearing to be a harmless helper change.
// Treat template surface changes as capability changes.

// TestTemplateContextHasNoMethods is the central invariant.
//
// text/template invokes exported methods through field-like expressions; any reachable type
// with such methods exposes those capabilities to template authors.
// Keep context as plain exported data with no methods.
//
// Failure indicates methods were added to webhookTemplateData/webhookItem.
// Assess potential access to hidden data before allowing that addition.
func TestTemplateContextHasNoMethods(t *testing.T) {
	for _, v := range []any{webhookTemplateData{}, webhookItem{}} {
		typ := reflect.TypeOf(v)
		if n := typ.NumMethod(); n != 0 {
			var names []string
			for i := 0; i < n; i++ {
				names = append(names, typ.Method(i).Name)
			}
			t.Fatalf("%s exposes %d methods (%s): text/template can call them, "+
				"which hands those methods' capabilities to template authors", typ.Name(), n, strings.Join(names, ", "))
		}
	}
}

// TestTemplateFuncsAreMinimal locks the exposed function set.
//
// Each FuncMap function adds a capability; allow only JSON serialization helpers json/jsons,
// never file reads, requests, or command execution.
func TestTemplateFuncsAreMinimal(t *testing.T) {
	var got []string
	for name := range webhookTemplateFuncs {
		got = append(got, name)
	}
	sort.Strings(got)
	want := []string{"json", "jsons"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("template function set changed: got %v, want %v. Before adding a function, confirm it does not widen the capability surface "+
			"(no file reads/writes, no network requests, no command execution)", got, want)
	}
}

// TestTemplateCannotReachUnknownData checks out-of-bounds template access.
// Unknown fields must fail rather than disclose data, and diagnostics must stay free of
func TestTemplateCannotReachUnknownData(t *testing.T) {
	_, err := renderWebhookBody(`{"x": {{.Environment}}, "y": {{.Env}}}`, singleMsg())
	if err == nil {
		t.Fatal("accessing a missing field should error")
	}
	// actual finding titles/summaries from context.
	for _, leak := range []string{"SQL\u6ce8\u5165", "\u53c2\u6570 id"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("template error leaked message content %q: %v", leak, err)
		}
	}
}

// TestTemplateRenderFailsPermanently classifies bad templates as permanent configuration errors.
// Otherwise each delivery wastes three backoff cycles on the same typo.
func TestTemplateRenderFailsPermanently(t *testing.T) {
	cfg := map[string]any{
		"url":           "https://example.com/hook",
		"body_template": `{{.Items.`,
	}
	if err := (webhookChannel{}).Validate(cfg); err == nil {
		t.Fatal("template syntax errors should be blocked at save time")
	}
	// Direct sends bypassing validation must also classify rendering errors permanent.
	_, err := (webhookChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("a bad template should be a permanent failure, got %v", err)
	}
}

// TestTemplateCanOnlyProduceJSON requires valid JSON output,
// preventing templates from generating plain text to trigger other protocols.
func TestTemplateCanOnlyProduceJSON(t *testing.T) {
	// Valid templates pass.
	ok := map[string]any{"url": "https://example.com/hook", "body_template": `{"t":{{json .Title}}}`}
	if err := (webhookChannel{}).Validate(ok); err != nil {
		t.Fatalf("a valid template should pass validation: %v", err)
	}
	// Reject non-JSON output rather than sending raw text.
	bad := map[string]any{"url": "http://127.0.0.1:1/hook", "body_template": `not json {{.Count}}`}
	_, err := (webhookChannel{}).Send(context.Background(), bad, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("output that is not JSON should be a permanent failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "valid JSON") {
		t.Errorf("the error should say it is a JSON problem, got %v", err)
	}
}
