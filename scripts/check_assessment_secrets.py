#!/usr/bin/env python3
"""Grep selected evidence exports, reports, logs or transcripts for known secrets.

Secret values are read from --accounts/--facts, placed in a private temporary
pattern file and never printed or passed in process arguments. Output contains
only offending filenames. Raw APKs/decompilation caches are inputs to analysis,
not evidence exports, and should not be supplied as files to scan.
"""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit


def values(accounts=None, facts=None):
    found = set()
    if accounts:
        data = json.loads(Path(accounts).read_text())
        for account in data if isinstance(data, list) else data.get("accounts", []):
            found.update(account.get(key, "") for key in ("username", "password", "totp_secret"))
    if facts:
        for item in json.loads(Path(facts).read_text()).get("secrets", []):
            value = item.get("value", "")
            found.add(value)
            try:
                parsed = urlsplit(value)
                if parsed.username:
                    found.add(unquote(parsed.username))
                if parsed.password:
                    found.add(unquote(parsed.password))
            except ValueError:
                pass
    found.discard("")
    if any("\n" in value or "\r" in value for value in found):
        raise ValueError("Multiline credentials require a binary-aware scanner")
    return found


def scan(secrets, files):
    if not secrets:
        raise ValueError("No known secret values were supplied")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="artex-secret-patterns-") as patterns:
        patterns.write("\n".join(sorted(secrets)) + "\n")
        patterns.flush()
        result = subprocess.run(["grep", "-F", "-l", "-a", "-f", patterns.name, "--", *map(str, files)],
                                capture_output=True, text=True, timeout=120)
    if result.returncode not in (0, 1):
        raise RuntimeError("grep could not scan every requested file")
    return result.stdout.splitlines()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accounts", type=Path)
    parser.add_argument("--facts", type=Path)
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        matches = scan(values(args.accounts, args.facts), args.files)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        # JSON parsing errors can contain source fragments, so print only type.
        print("Secret check failed: " + type(error).__name__)
        return 2
    if matches:
        print("Plaintext secret matches in:")
        print("\n".join(matches))
        return 1
    print("PASS: no known plaintext credentials in the selected files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
