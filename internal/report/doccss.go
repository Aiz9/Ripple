package report

import "fmt"

// docCSS returns the print stylesheet for the templated VAPT document. accent is
// the firm colour used for the cover project name, headings, and table headers.
func docCSS(accent string) string {
	return fmt.Sprintf(`
*{box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact;}
html,body{margin:0;padding:0;}
body{font-family:'Poppins','Liberation Sans','DejaVu Sans','Segoe UI',Arial,sans-serif;color:#222;font-size:10.5pt;line-height:1.5;}
@page{size:A4;margin:20mm;}
@page:first{margin:0;}

/* Cover (table layout: reliable in both Chrome and LibreOffice) */
table.cover{width:100%%;height:297mm;border-collapse:collapse;table-layout:fixed;page-break-after:always;}
table.cover td{border:0;}
.cover-left{width:62%%;vertical-align:top;padding:20mm 8mm 0 16mm;}
.cover-right{width:38%%;vertical-align:top;padding:0;}
.cover-wave{width:100%%;height:297mm;object-fit:cover;object-position:right top;display:block;}
.cover-logo{width:50mm;height:auto;display:block;}
.cover-title{margin-top:50mm;font-size:27pt;font-weight:700;color:#2b2b2b;line-height:1.14;}
.cover-project{margin-top:14mm;font-size:24pt;font-weight:600;color:%[1]s;line-height:1.1;}
.cover-date{margin-top:40mm;font-size:12pt;font-weight:600;letter-spacing:4px;color:#333;}

/* Flow */
.sheet{page-break-before:always;}
.runhead{text-align:right;color:#9a9a9a;font-size:8.5pt;border-bottom:1px solid #eee;padding-bottom:3px;margin-bottom:12px;}
h1{color:%[1]s;font-size:18pt;font-weight:700;margin:0 0 10px;border-bottom:2px solid %[1]s;padding-bottom:4px;}
h2{font-size:13pt;font-weight:600;margin:14px 0 6px;}
h4,h5,h6{margin:10px 0 4px;font-weight:600;}
p{margin:6px 0;}
ul,ol{margin:6px 0 6px 0;padding-left:20px;}
li{margin:2px 0;}
.muted{color:#888;}
code{font-family:'Courier New',monospace;background:#f3f3f3;padding:1px 4px;border-radius:3px;font-size:9pt;}
pre{background:#f6f6f6;border:1px solid #e3e3e3;border-radius:4px;padding:8px;font-family:'Courier New',monospace;font-size:8.5pt;white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere;}
a{color:%[1]s;text-decoration:none;word-break:break-all;}

/* Vulnerability list table */
table.vlist{width:166mm;max-width:100%%;border-collapse:collapse;margin-top:6px;}
table.vlist th{background:%[1]s;color:#fff;font-weight:600;padding:7px 8px;text-align:left;font-size:10pt;}
table.vlist td{border:1px solid #ddd;padding:7px 8px;vertical-align:middle;}
table.vlist td.sn{font-weight:700;text-align:center;width:36px;}

/* Finding detail */
.finding{page-break-before:always;}
.fhead{margin-bottom:8px;}
.fhead .fid{background:%[1]s;color:#fff;font-weight:700;padding:3px 11px;border-radius:4px;font-size:12pt;margin-right:10px;}
.fhead .fname{font-size:13pt;font-weight:600;}
table.fmeta{width:166mm;max-width:100%%;border-collapse:collapse;}
table.fmeta th{width:34mm;text-align:left;vertical-align:top;background:#f7f7f7;color:#444;font-weight:600;border:1px solid #e2e2e2;padding:7px 9px;}
table.fmeta td{border:1px solid #e2e2e2;padding:7px 9px;vertical-align:top;word-break:break-word;overflow-wrap:anywhere;}
table.fmeta td p:first-child{margin-top:0;}
.freport{margin-top:12px;}

/* Appendix */
table.appendix{width:166mm;max-width:100%%;border-collapse:collapse;margin-top:8px;}
table.appendix th{background:%[1]s;color:#fff;text-align:left;padding:7px 9px;}
table.appendix td{border:1px solid #ddd;padding:7px 9px;vertical-align:top;}

/* Severity colours */
.sev-critical{color:#7d0a0a;font-weight:700;}
.sev-high{color:#d32f2f;font-weight:700;}
.sev-medium{color:#e67e22;font-weight:700;}
.sev-low{color:#2e7d32;font-weight:700;}
.sev-info{color:#607d8b;font-weight:700;}
`, accent)
}
