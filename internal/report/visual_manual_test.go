package report

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Aiz9/ripple/internal/db"
)

// Gated manual render: RIPPLE_VISUAL=<outdir> go test ./internal/report -run TestVisualRender
func TestVisualRender(t *testing.T) {
	outDir := os.Getenv("RIPPLE_VISUAL")
	if outDir == "" {
		t.Skip("set RIPPLE_VISUAL=<dir> to render sample pdf/docx")
	}
	bind := func(method, url string, status int) db.FindingTrafficBinding {
		return db.FindingTrafficBinding{Role: "request", Snapshot: db.TrafficEvidenceSnapshot{Method: method, URL: url, Status: status}}
	}
	fs := []*db.DBFinding{
		{ID: 1, Name: "Client-Side Validation Bypass Allows Unauthorized Self-Approval", VulnClass: "Broken Access Control", Severity: "high", Status: "pending",
			Summary: "The application relies on client-side controls to restrict modification of sensitive fields within a maker-checker workflow. These restrictions are not enforced server-side.",
			Report:  "## Security Impact\n\nAn attacker can alter restricted data fields and **approve their own** unauthorized changes, defeating segregation of duties.\n\n## Recommendation\n\n- Enforce strict server-side validation.\n- Implement robust role-based access control on every update and approval.\n- Enforce separation of duties in the maker-checker workflow.\n\n## References\n\n- [OWASP A01:2021](https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/)",
			TrafficBindings: []db.FindingTrafficBinding{bind("POST", "http://bankxp-admin.example.com/customer/modify/42", 200)}},
		{ID: 2, Name: "Public Exposure of OAuth Configuration Including Client Secret", VulnClass: "Sensitive Data Exposure", Severity: "high", Status: "pending",
			Summary: "The application exposes its OAuth configuration endpoint without authentication, disclosing the client id and client secret.",
			TrafficBindings: []db.FindingTrafficBinding{bind("GET", "http://bankxp-admin.example.com/.well-known/oauth", 200)}},
		{ID: 3, Name: "Stored XSS via Malicious SVG Upload", VulnClass: "Cross-Site Scripting", Severity: "medium", Status: "pending",
			Summary:  "An SVG containing `<script>alert(1)</script>` is stored and served with image/svg+xml, executing in the victim's session.",
			Evidence: "Request:\n```\nPOST /upload HTTP/1.1\nContent-Type: image/svg+xml\n```",
			TrafficBindings: []db.FindingTrafficBinding{bind("POST", "http://bankxp.example.com/upload", 201)}},
		{ID: 4, Name: "CORS Misconfiguration – Arbitrary Origin Access", VulnClass: "Security Misconfiguration", Severity: "info", Status: "pending",
			Summary: "The API reflects any Origin with Access-Control-Allow-Credentials: true."},
	}
	html := FindingsHTML("BankXP Admin", fs, LoadBranding("../../report_assets"), time.Now())
	_ = os.WriteFile(outDir+"/report.html", []byte(html), 0o644)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for _, f := range []string{"pdf", "docx"} {
		data, _, err := RenderDoc(ctx, []byte(html), f)
		if err != nil {
			t.Errorf("render %s: %v", f, err)
			continue
		}
		if err := os.WriteFile(outDir+"/report."+f, data, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s/report.%s (%d bytes)", outDir, f, len(data))
	}
}
