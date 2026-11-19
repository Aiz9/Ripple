package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Aiz9/ripple/internal/db"
)

func TestMdToHTMLEscapesAndFormats(t *testing.T) {
	// Finding content may echo attacker/target data; it must never inject markup.
	got := mdToHTML("A <script>alert(1)</script> & **bold** `code` [x](http://e.com)")
	if strings.Contains(got, "<script>") {
		t.Fatalf("script tag not escaped: %s", got)
	}
	for _, want := range []string{"&lt;script&gt;", "&amp;", "<strong>bold</strong>", "<code>code</code>", `<a href="http://e.com">x</a>`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
}

func TestMdToHTMLBlocks(t *testing.T) {
	got := mdToHTML("# Title\n\n- one\n- two\n\n1. first\n\n```\nx<y\n```")
	for _, want := range []string{"<h4>Title</h4>", "<ul><li>one</li><li>two</li></ul>", "<ol><li>first</li></ol>", "<pre>x&lt;y\n</pre>"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
}

func TestAssignFindingIDs(t *testing.T) {
	fs := []*db.DBFinding{
		{Severity: "high"}, {Severity: "high"}, {Severity: "medium"}, {Severity: "informational"}, {Severity: ""},
	}
	got := assignFindingIDs(fs)
	want := []string{"H1", "H2", "M1", "I1", "I2"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("id[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestFindingsHTMLUsesTaskNameAndEscapes(t *testing.T) {
	fs := []*db.DBFinding{{ID: 1, Name: "SQLi <b>", Severity: "high", Summary: "x"}}
	html := FindingsHTML("Acme <Prod>", fs, Branding{CoverTitle: "T", AccentColor: "#000"}, time.Now())
	if !strings.Contains(html, "Acme &lt;Prod&gt;") {
		t.Error("cover should carry escaped task name")
	}
	if !strings.Contains(html, "SQLi &lt;b&gt;") {
		t.Error("finding name should be escaped")
	}
	if strings.Contains(html, "<b>") {
		t.Error("raw markup leaked from finding name")
	}
}
