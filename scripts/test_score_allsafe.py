import json
import tempfile
import unittest
from pathlib import Path

from score_allsafe import load_findings, score


class AllSafeScoreTests(unittest.TestCase):
    def test_provider_injection_cannot_count_as_local_challenge(self):
        expected = {"items": [{"id": "local_sql", "check_ids": ["masvs.code.local_sqli"], "match": ["SQL injection"]}]}
        findings = [{"id": "f", "title": "SQL injection in exported provider", "check_id": "masvs.platform.provider_sqli", "status": "validated", "automated": True}]
        rows, unmatched = score(findings, expected)
        self.assertEqual(rows[0]["state"], "missed")
        self.assertEqual(len(unmatched), 1)

    def test_json_recognizes_typed_reviewer_and_rejects_label_alone(self):
        check = "masvs.code.local_sqli"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assessment.json"
            path.write_text(json.dumps({"findings": [
                {"id": "a", "status": "validated", "check_id": check, "validated_by": "auto:" + check + "@1"},
                {"id": "b", "status": "validated", "check_id": check, "automated": True},
                {"id": "c", "status": "validated", "check_id": check, "validated_by": "auto:another.check@1"},
            ]}))
            findings = load_findings(str(path))
        self.assertEqual([f["automated"] for f in findings], [True, False, False])


if __name__ == "__main__":
    unittest.main()
