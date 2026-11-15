import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from check_assessment_secrets import scan


class SecretScanTests(unittest.TestCase):
    def test_detects_literal_secrets_without_printing_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = "literal-fixture-password.[not-regex]"
            accounts = root / "accounts.json"
            accounts.write_text(json.dumps([{"role": "primary", "password": secret}]))
            evidence = root / "evidence.json"
            evidence.write_text(json.dumps({"detail": secret}))
            script = Path(__file__).with_name("check_assessment_secrets.py")
            result = subprocess.run([sys.executable, str(script), "--accounts", str(accounts), str(evidence)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(secret, result.stdout + result.stderr)
            self.assertIn(str(evidence), result.stdout)
            evidence.write_text('{"detail":"***"}')
            self.assertEqual(scan({secret}, [evidence]), [])


if __name__ == "__main__":
    unittest.main()
