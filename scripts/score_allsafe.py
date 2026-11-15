#!/usr/bin/env python3
"""Score an ARTEX final report against testdata/allsafe_expected.json.

Usage: scripts/score_allsafe.py REPORT [--expected FILE] [--json]

REPORT is final.json (preferred) or a Markdown report. A finding counts as
"proven" only when its validation status is validated; "automated" additionally
requires an automated check label. Exit status is always 0 unless the input is
unreadable, so the score can be recorded even for a weak run.
"""

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_findings(path):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    if path.endswith(".json"):
        doc = json.loads(text)
        out = []
        for f in doc.get("findings", []):
            status = str(f.get("validation_status") or f.get("status") or "")
            out.append({
                "id": f.get("id", ""),
                "title": f.get("title", ""),
                "status": status,
                "check_id": f.get("check_id", ""),
                "automated": str(f.get("validated_by", "")).startswith("auto:" + str(f.get("check_id", "")) + "@"),
            })
        return out
    # Markdown: "### <id> — <title>" followed by "- Validation: <status>" lines.
    out = []
    current = None
    for line in text.splitlines():
        m = re.match(r"^###\s+(\S+)\s+[—-]\s+(.*)$", line)
        if m:
            current = {"id": m.group(1), "title": m.group(2).strip(), "status": "", "check_id": "", "automated": False}
            out.append(current)
            continue
        if current is None:
            continue
        m = re.match(r"^-\s+Validation:\s+(.*)$", line)
        if m:
            value = m.group(1).strip()
            current["status"] = value.split()[0].strip("*") if value else ""
            current["automated"] = "automated" in value
            c = re.search(r"automated:\s*([\w.\-]+)", value)
            if c:
                current["check_id"] = c.group(1)
        m = re.match(r"^-\s+Check:\s+`?([\w.\-]+)`?", line)
        if m:
            current["check_id"] = m.group(1)
    # Only headings inside the findings part are findings; evidence headings
    # ("### Evidence …") never carry a validation line.
    return [f for f in out if f["status"]]


def score(findings, expected):
    items = expected["items"]
    used = set()
    result = {}
    # Exact check-id matches take precedence over title heuristics.
    for item in items:
        for i, f in enumerate(findings):
            if i not in used and f["check_id"] and f["check_id"] in item.get("check_ids", []):
                result.setdefault(item["id"], []).append(f)
                used.add(i)
    for item in items:
        patterns = [re.compile(p, re.I) for p in item.get("match", [])]
        for i, f in enumerate(findings):
            if i in used:
                continue
            # A typed check for another procedure cannot satisfy this challenge
            # through a broad word such as "SQL", "PIN" or "crypto".
            if f["check_id"]:
                continue
            if any(p.search(f["title"]) for p in patterns):
                result.setdefault(item["id"], []).append(f)
                used.add(i)
    rows = []
    for item in items:
        matches = result.get(item["id"], [])
        proven = [f for f in matches if f["status"].startswith("validated")]
        automated = [f for f in proven if f["automated"]]
        state = "missed"
        if automated:
            state = "automated"
        elif proven:
            state = "validated"
        elif matches:
            state = "candidate"
        rows.append({"id": item["id"], "state": state, "optional": bool(item.get("optional")),
                     "findings": [f"{f['id']} [{f['status']}] {f['title']}" for f in matches]})
    unmatched = [f for i, f in enumerate(findings) if i not in used]
    return rows, unmatched


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report")
    parser.add_argument("--expected", default=str(ROOT / "testdata" / "allsafe_expected.json"))
    parser.add_argument("--json", action="store_true", help="print machine-readable result")
    args = parser.parse_args()
    try:
        expected = json.loads(Path(args.expected).read_text())
        findings = load_findings(args.report)
    except (OSError, ValueError) as exc:
        print(f"score_allsafe: cannot read input: {exc}", file=sys.stderr)
        return 2
    rows, unmatched = score(findings, expected)
    total = len(rows)
    automated = sum(r["state"] == "automated" for r in rows)
    validated = sum(r["state"] in ("automated", "validated") for r in rows)
    detected = sum(r["state"] != "missed" for r in rows)
    summary = {"report": args.report, "expected": total, "automated": automated, "validated": validated,
               "detected": detected, "findings": len(findings), "unmatched_findings": len(unmatched), "rows": rows}
    if args.json:
        print(json.dumps(summary, indent=2))
        return 0
    for r in rows:
        mark = {"automated": "✔", "validated": "✓", "candidate": "~", "missed": "✗"}[r["state"]]
        opt = " (optional)" if r["optional"] else ""
        print(f"{mark} {r['id']:<28} {r['state']:<10}{opt}  {'; '.join(r['findings'])[:120]}")
    print(f"\nScore: automated {automated}/{total} · validated {validated}/{total} · detected {detected}/{total} · "
          f"report findings {len(findings)} ({len(unmatched)} unmatched)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
