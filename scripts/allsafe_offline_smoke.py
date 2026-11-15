#!/usr/bin/env python3
"""Run the AllSafe CLI smoke test with all app-UID IPv4/IPv6 egress rejected.

Requires adb, root via su 0, iptables/ip6tables, Go, jadx, aapt2 and a PDF
converter. This checks local proofs only; it cannot validate network findings.
The finally block removes only this invocation's uniquely tagged firewall rules.
"""

import argparse
import hashlib
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import uuid


ROOT = Path(__file__).resolve().parent.parent
EXPECTED = "d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="127.0.0.1:6555")
    parser.add_argument("--apk", type=Path, default=ROOT / "validation/corpus/allsafe.apk")
    parser.add_argument("--observe-seconds", type=int, default=300)
    args = parser.parse_args()
    with args.apk.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != EXPECTED:
            raise RuntimeError("APK does not match the approved AllSafe benchmark")

    def adb(*parts, check=True):
        return subprocess.run(["adb", "-s", args.device, *parts], capture_output=True,
                              text=True, timeout=30, check=check)

    package = adb("shell", "dumpsys", "package", "infosecadventures.allsafe").stdout
    match = re.search(r"\buserId=(\d+)\b", package)
    if not match or int(match[1]) < 10000:
        raise RuntimeError("Cannot establish an isolated application UID")
    uid = match[1]
    proxy = adb("shell", "settings", "get", "global", "http_proxy").stdout
    tag = "artex-smoke-" + uuid.uuid4().hex[:16]
    rule = ["-m", "owner", "--uid-owner", uid, "-m", "comment", "--comment", tag, "-j", "REJECT"]
    installed = []
    proc = None
    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    log = out / (tag + ".log")

    def interrupted(*_):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, interrupted)
    try:
        for tool in ("iptables", "ip6tables"):
            adb("shell", "su", "0", tool, "-w", "5", "-I", "OUTPUT", "1", *rule)
            installed.append(tool)
            adb("shell", "su", "0", tool, "-w", "5", "-C", "OUTPUT", *rule)
        print("App UID egress blocked for IPv4 and IPv6; starting local-only assessment.", flush=True)
        with tempfile.TemporaryDirectory(prefix="artex-offline-smoke-") as temp:
            binary = str(Path(temp) / "apkassess")
            subprocess.run(["go", "build", "-o", binary, "./cmd/apkassess"], cwd=ROOT, check=True, timeout=180)
            with log.open("w") as stream:
                proc = subprocess.Popen([binary, "--apk", str(args.apk.resolve()), "--device", args.device,
                                         "--out", str(out), "--budget-minutes", "15", "--observe-seconds", str(args.observe_seconds)],
                                        cwd=ROOT, stdout=stream, stderr=stream, start_new_session=True)
                code = proc.wait(timeout=1200)
                if code:
                    raise RuntimeError(f"Assessment failed with exit {code}; inspect {log}")
        print(f"Assessment log: {log}", flush=True)
    finally:
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=10)
        errors = []
        # Stop the assessed process before lifting egress restrictions so a
        # queued request cannot escape when the temporary rules are removed.
        if installed:
            if adb("shell", "am", "force-stop", "infosecadventures.allsafe", check=False).returncode:
                errors.append("Could not stop AllSafe before removing egress rules")
        for tool in reversed(installed):
            if adb("shell", "su", "0", tool, "-w", "5", "-D", "OUTPUT", *rule, check=False).returncode:
                errors.append(f"Could not remove {tool} rule tagged {tag}")
        if adb("shell", "settings", "get", "global", "http_proxy").stdout != proxy:
            errors.append("Device proxy differs from the pre-run setting")
        if errors:
            raise RuntimeError("; ".join(errors))
        print("Owned firewall rules removed; device proxy unchanged.", flush=True)


if __name__ == "__main__":
    main()
