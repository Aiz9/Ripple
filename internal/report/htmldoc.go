package report

import (
	"fmt"
	"html"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Aiz9/ripple/internal/db"
)

// FindingsHTML renders the task's findings as a self-contained A4 HTML document
// laid out like the firm VAPT template: branded cover (title + task name),
// Summary, Scope, a Vulnerability List table, per-finding Vulnerability Details,
// and the Severity appendix. The HTML is converted to PDF/DOCX by RenderDoc.
//
// taskName becomes the red project title on the cover. Fields the template has
// but Ripple does not store (CWE, CVSS score) are omitted; the detailed Markdown
// Report is rendered in place of the prose sections.
func FindingsHTML(taskName string, fs []*db.DBFinding, b Branding, generatedAt time.Time) string {
	items := append([]*db.DBFinding(nil), fs...)
	sortFindingsForExport(items)
	ids := assignFindingIDs(items)

	var h strings.Builder
	h.WriteString("<!doctype html><html><head><meta charset=\"utf-8\">")
	h.WriteString(`<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">`)
	h.WriteString("<style>" + docCSS(b.AccentColor) + "</style></head><body>")

	writeCover(&h, taskName, b, generatedAt)
	writeSummaryScope(&h, items, b)
	writeVulnList(&h, items, ids)
	writeVulnDetails(&h, items, ids, b.AccentColor)
	writeAppendix(&h, b)

	h.WriteString("</body></html>")
	return h.String()
}

// writeCover builds a table-based cover (left: logo/title/task name/date,
// right: the branded wave strip). A table layout is used instead of absolute
// positioning so both Chrome (PDF) and LibreOffice (DOCX) render it the same.
func writeCover(h *strings.Builder, taskName string, b Branding, at time.Time) {
	h.WriteString(`<table class="cover"><tr><td class="cover-left">`)
	if b.LogoDataURI != "" {
		fmt.Fprintf(h, `<img class="cover-logo" src="%s">`, b.LogoDataURI)
	}
	fmt.Fprintf(h, `<div class="cover-title">%s</div>`, html.EscapeString(b.CoverTitle))
	fmt.Fprintf(h, `<div class="cover-project">%s</div>`, html.EscapeString(nz(taskName, "Security Assessment")))
	fmt.Fprintf(h, `<div class="cover-date">%s</div>`, strings.ToUpper(at.Format("2 January, 2006")))
	h.WriteString(`</td><td class="cover-right">`)
	if b.CoverDataURI != "" {
		fmt.Fprintf(h, `<img class="cover-wave" src="%s">`, b.CoverDataURI)
	}
	h.WriteString(`</td></tr></table>`)
}

func writeSummaryScope(h *strings.Builder, fs []*db.DBFinding, b Branding) {
	h.WriteString(`<section class="sheet">`)
	if b.CompanyName != "" {
		fmt.Fprintf(h, `<div class="runhead">%s</div>`, html.EscapeString(b.CompanyName))
	}
	if b.Summary != "" {
		h.WriteString(`<h1>Summary</h1><p>` + html.EscapeString(b.Summary) + `</p>`)
	}
	h.WriteString(`<h1>Scope</h1>`)
	scope := collectScope(fs)
	if len(scope) == 0 {
		h.WriteString(`<p class="muted">No in-scope endpoints were recorded with the findings.</p>`)
	} else {
		h.WriteString(`<ul>`)
		for _, s := range scope {
			fmt.Fprintf(h, `<li>%s</li>`, html.EscapeString(s))
		}
		h.WriteString(`</ul>`)
	}
	h.WriteString(`</section>`)
}

func writeVulnList(h *strings.Builder, fs []*db.DBFinding, ids []string) {
	h.WriteString(`<section class="sheet"><h1>Vulnerability List</h1>`)
	if len(fs) == 0 {
		h.WriteString(`<p class="muted">No findings were recorded for this task.</p></section>`)
		return
	}
	h.WriteString(`<table class="vlist" width="620"><colgroup><col width="44"><col width="320"><col width="124"><col width="132"></colgroup><thead><tr><th>S.N.</th><th>Vulnerability Name</th><th>Severity</th><th>Status</th></tr></thead><tbody>`)
	for i, f := range fs {
		fmt.Fprintf(h, `<tr><td class="sn">%s</td><td>%s</td><td class="%s">%s</td><td>%s</td></tr>`,
			ids[i], html.EscapeString(findingTitle(f)), sevClass(f.Severity), sevLabel(f.Severity), html.EscapeString(statusLabel(f.Status)))
	}
	h.WriteString(`</tbody></table></section>`)
}

func writeVulnDetails(h *strings.Builder, fs []*db.DBFinding, ids []string, accent string) {
	if len(fs) == 0 {
		return
	}
	h.WriteString(`<section class="sheet"><h1>Vulnerability Details</h1></section>`)
	for i, f := range fs {
		h.WriteString(`<section class="finding">`)
		fmt.Fprintf(h, `<div class="fhead"><span class="fid">%s</span> <span class="fname">%s</span></div>`,
			ids[i], html.EscapeString(findingTitle(f)))
		// Legacy HTML width attributes (px): LibreOffice honors these far more
		// reliably than CSS widths, keeping the content column inside the page.
		h.WriteString(`<table class="fmeta" width="620"><colgroup><col width="120"><col width="500"></colgroup><tbody>`)
		row := func(k, vHTML string) { fmt.Fprintf(h, `<tr><th>%s</th><td>%s</td></tr>`, k, vHTML) }
		if f.VulnClass != "" {
			row("Category", html.EscapeString(f.VulnClass))
		}
		row("Severity", `<span class="`+sevClass(f.Severity)+`">`+sevLabel(f.Severity)+`</span>`)
		row("Status", html.EscapeString(statusLabel(f.Status)))
		if s := strings.TrimSpace(f.Summary); s != "" {
			row("Description", mdToHTML(s))
		}
		if eps := findingEndpoints(f); len(eps) > 0 {
			var lb strings.Builder
			lb.WriteString("<ul>")
			for _, e := range eps {
				fmt.Fprintf(&lb, "<li>%s</li>", html.EscapeString(e))
			}
			lb.WriteString("</ul>")
			row("Affected Endpoint", lb.String())
		}
		if ev := strings.TrimSpace(f.Evidence); ev != "" {
			row("Evidence", mdToHTML(ev))
		}
		h.WriteString(`</tbody></table>`)
		if rep := strings.TrimSpace(f.Report); rep != "" {
			h.WriteString(`<div class="freport">` + mdToHTML(rep) + `</div>`)
		}
		h.WriteString(`</section>`)
	}
}

func writeAppendix(h *strings.Builder, b Branding) {
	if len(b.Appendix) == 0 {
		return
	}
	h.WriteString(`<section class="sheet"><h1>Appendix</h1><h2>Severity and Risk Matrix</h2>`)
	h.WriteString(`<p>Each finding is assigned a severity rating of critical, high, medium, low, or informational, calculated using the CVSS 3.1 Calculator. The rating reflects the priority with which each finding should be viewed and its potential impact on the Confidentiality, Integrity, and Availability (CIA) of the organization's data.</p>`)
	h.WriteString(`<table class="appendix" width="620"><colgroup><col width="120"><col width="500"></colgroup><thead><tr><th>Rating</th><th>Severity Rating Definition</th></tr></thead><tbody>`)
	for _, d := range b.Appendix {
		fmt.Fprintf(h, `<tr><td class="%s">%s</td><td>%s</td></tr>`,
			sevClass(d.Severity), html.EscapeString(d.Severity), html.EscapeString(d.Definition))
	}
	h.WriteString(`</tbody></table></section>`)
}

// --- helpers ---------------------------------------------------------------

// assignFindingIDs produces template IDs (H1, M2, L1, I1…) per severity group,
// in the already-sorted order of fs.
func assignFindingIDs(fs []*db.DBFinding) []string {
	out := make([]string, len(fs))
	n := map[string]int{}
	for i, f := range fs {
		p := sevPrefix(f.Severity)
		n[p]++
		out[i] = fmt.Sprintf("%s%d", p, n[p])
	}
	return out
}

func sevKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "informational", "information":
		return "info"
	case "":
		return "info"
	}
	return s
}

func sevPrefix(s string) string {
	switch sevKey(s) {
	case "critical":
		return "C"
	case "high":
		return "H"
	case "medium":
		return "M"
	case "low":
		return "L"
	default:
		return "I"
	}
}

func sevLabel(s string) string {
	switch sevKey(s) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Informational"
	}
}

func sevClass(s string) string { return "sev-" + sevKey(s) }

func statusLabel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "pending":
		return "Not Fixed"
	case "resolved", "fixed":
		return "Fixed"
	case "false_positive":
		return "False Positive"
	case "ignored":
		return "Ignored"
	}
	return s
}

// findingEndpoints returns distinct "METHOD url" lines from traffic bindings.
func findingEndpoints(f *db.DBFinding) []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range f.TrafficBindings {
		e := strings.TrimSpace(b.Snapshot.Method + " " + b.Snapshot.URL)
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out
}

// collectScope gathers distinct scheme://host targets across all findings.
var hostRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s]+`)

func collectScope(fs []*db.DBFinding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		for _, b := range f.TrafficBindings {
			if m := hostRe.FindString(b.Snapshot.URL); m != "" && !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}

// --- minimal Markdown → HTML (self-contained; no dependency) ---------------

var (
	mdCode = regexp.MustCompile("`([^`]+)`")
	mdBold = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	mdLink = regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)\)`)
)

// mdInline applies code/bold/link formatting to already HTML-escaped text.
func mdInline(escaped string) string {
	escaped = mdCode.ReplaceAllString(escaped, "<code>$1</code>")
	escaped = mdBold.ReplaceAllString(escaped, "<strong>$1</strong>")
	escaped = mdLink.ReplaceAllString(escaped, `<a href="$2">$1</a>`)
	return escaped
}

// mdToHTML converts a small but common subset of Markdown to safe HTML:
// ATX headings, unordered/ordered lists, fenced code blocks, blank-line
// paragraphs, and inline bold/code/links. All text is HTML-escaped first, so
// finding content (which may echo attacker/target data) can never inject markup.
func mdToHTML(src string) string {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	var out strings.Builder
	var para []string
	inList, inOrdered, inCode := false, false, false

	flushPara := func() {
		if len(para) > 0 {
			out.WriteString("<p>" + strings.Join(para, "<br>") + "</p>")
			para = para[:0]
		}
	}
	closeList := func() {
		if inList {
			if inOrdered {
				out.WriteString("</ol>")
			} else {
				out.WriteString("</ul>")
			}
			inList, inOrdered = false, false
		}
	}

	for _, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "```") {
			if inCode {
				out.WriteString("</pre>")
				inCode = false
			} else {
				flushPara()
				closeList()
				out.WriteString("<pre>")
				inCode = true
			}
			continue
		}
		if inCode {
			out.WriteString(html.EscapeString(ln) + "\n")
			continue
		}
		t := strings.TrimSpace(ln)
		if t == "" {
			flushPara()
			closeList()
			continue
		}
		// Headings.
		if m := regexp.MustCompile(`^(#{1,6})\s+(.*)$`).FindStringSubmatch(t); m != nil {
			flushPara()
			closeList()
			lvl := len(m[1]) + 3
			if lvl > 6 {
				lvl = 6
			}
			fmt.Fprintf(&out, "<h%d>%s</h%d>", lvl, mdInline(html.EscapeString(m[2])), lvl)
			continue
		}
		// Unordered list item.
		if m := regexp.MustCompile(`^[-*+•●]\s+(.*)$`).FindStringSubmatch(t); m != nil {
			flushPara()
			if inList && inOrdered {
				closeList()
			}
			if !inList {
				out.WriteString("<ul>")
				inList, inOrdered = true, false
			}
			out.WriteString("<li>" + mdInline(html.EscapeString(m[1])) + "</li>")
			continue
		}
		// Ordered list item.
		if m := regexp.MustCompile(`^\d+[.)]\s+(.*)$`).FindStringSubmatch(t); m != nil {
			flushPara()
			if inList && !inOrdered {
				closeList()
			}
			if !inList {
				out.WriteString("<ol>")
				inList, inOrdered = true, true
			}
			out.WriteString("<li>" + mdInline(html.EscapeString(m[1])) + "</li>")
			continue
		}
		closeList()
		para = append(para, mdInline(html.EscapeString(t)))
	}
	if inCode {
		out.WriteString("</pre>")
	}
	flushPara()
	closeList()
	return out.String()
}
