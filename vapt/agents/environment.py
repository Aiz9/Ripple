"""Environment agent: verifies device, root, frida, proxy, CA, and app installation."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

from vapt.agents.base import BaseAgent
from vapt.core import Finding, RunContext
from vapt.kill_switch import KillSwitch


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str


class EnvironmentAgent(BaseAgent):
    name = "environment"
    step_budget = 50
    time_budget = 300.0

    def __init__(self, ctx: RunContext, kill_switch: KillSwitch, config: dict | None = None):
        super().__init__(ctx, kill_switch, config)
        self.serial = ctx.device_serial
        self.package = ctx.package_name
        self.checks: list[CheckResult] = []

    def _adb(self, *args: str, timeout: int = 30) -> tuple[str, int]:
        cmd = ["adb", "-s", self.serial, *args]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return proc.stdout.strip(), proc.returncode
        except subprocess.TimeoutExpired:
            return "", -1
        except FileNotFoundError:
            return "adb not found in PATH", -2

    def _shell(self, *args: str, timeout: int = 30) -> tuple[str, int]:
        return self._adb("shell", *args, timeout=timeout)

    def _record(self, name: str, passed: bool, detail: str) -> CheckResult:
        r = CheckResult(name=name, passed=passed, detail=detail)
        self.checks.append(r)
        level = "PASS" if passed else "FAIL"
        self.log.info("[%s] %s: %s", level, name, detail)
        return r

    def execute(self) -> list[Finding]:
        self.step()
        self.restore_snapshot()

        self.step()
        self.check_adb_connection()

        self.step()
        self.check_root()

        self.step()
        self.check_frida()

        self.step()
        self.check_proxy_ca()

        self.step()
        self.check_app_installed()

        failed = [c for c in self.checks if not c.passed]
        if failed:
            summary = "; ".join(f"{c.name}: {c.detail}" for c in failed)
            raise EnvironmentError(f"Environment checks failed: {summary}")

        return []

    def restore_snapshot(self) -> None:
        gmtool = shutil.which("gmtool")
        if gmtool:
            try:
                proc = subprocess.run(
                    [gmtool, "admin", "snapshots", "restore", "--name", "clean"],
                    capture_output=True, text=True, timeout=120,
                )
                if proc.returncode == 0:
                    self._record("snapshot_restore", True, "Restored 'clean' snapshot via gmtool")
                    return
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        out, rc = self._shell(
            "am", "broadcast",
            "-a", "com.genymobile.genymotion.SNAPSHOT_RESTORE",
            "--es", "snapshot_name", "clean",
            timeout=60,
        )
        if rc == 0 and "result=0" in out:
            self._record("snapshot_restore", True, "Restored snapshot via broadcast")
        else:
            self._record("snapshot_restore", False, f"Snapshot restore failed (rc={rc}): {out[:200]}")

    def check_adb_connection(self) -> None:
        out, rc = self._adb("get-state", timeout=10)
        if rc == 0 and out == "device":
            self._record("adb_connection", True, f"Device {self.serial} state: device")
        else:
            self._record("adb_connection", False, f"Expected state 'device', got '{out}' (rc={rc})")

    def check_root(self) -> None:
        out, rc = self._shell("id", "-u")
        if rc == 0 and out.strip() == "0":
            self._record("root", True, "adb shell runs as uid 0")
            return

        out, rc = self._adb("shell", "su", "0", "id", "-u", timeout=10)
        if rc == 0 and out.strip() == "0":
            self._record("root", True, "Root available via su binary")
            return

        self._record("root", False, f"Root not available (id output: {out[:100]})")

    def check_frida(self) -> None:
        device_version, rc = self._shell(
            "/data/local/tmp/frida-server", "--version", timeout=10,
        )
        if rc != 0 or not device_version:
            self._record("frida_server", False,
                         f"frida-server not responding at /data/local/tmp/frida-server (rc={rc})")
            return

        device_version = device_version.strip().split("\n")[0]

        try:
            import frida
            client_version = frida.__version__
        except ImportError:
            self._record("frida_client", False, "Python frida module not installed")
            return

        dev_major = device_version.rsplit(".", 1)[0] if "." in device_version else device_version
        cli_major = client_version.rsplit(".", 1)[0] if "." in client_version else client_version

        if dev_major != cli_major:
            self._record("frida_version", False,
                         f"Version mismatch: server={device_version}, client={client_version}")
            return
        self._record("frida_version", True,
                     f"server={device_version}, client={client_version}")

        abi, _ = self._shell("getprop", "ro.product.cpu.abi")
        abi = abi.strip()
        server_file_out, _ = self._shell("file", "/data/local/tmp/frida-server")
        arch_ok = False
        abi_to_elf = {
            "arm64-v8a": "aarch64",
            "armeabi-v7a": "ARM",
            "x86_64": "x86-64",
            "x86": "Intel 80386",
        }
        expected_elf = abi_to_elf.get(abi, "")
        if expected_elf and expected_elf.lower() in server_file_out.lower():
            arch_ok = True

        if arch_ok:
            self._record("frida_arch", True, f"frida-server arch matches device ABI ({abi})")
        else:
            self._record("frida_arch", False,
                         f"frida-server may not match device ABI '{abi}': {server_file_out[:150]}")

    def check_proxy_ca(self) -> None:
        certs_dir = "/system/etc/security/cacerts"
        out, rc = self._shell("ls", certs_dir)
        if rc != 0:
            out, rc = self._shell("ls", "/apex/com.android.conscrypt/cacerts")
            certs_dir = "/apex/com.android.conscrypt/cacerts"

        if rc != 0:
            self._record("proxy_ca", False, f"Cannot list system CA directory (rc={rc})")
            return

        ca_hash = self.config.get("mitmproxy_ca_hash", "")
        if ca_hash:
            cert_file = f"{certs_dir}/{ca_hash}.0"
            out_check, rc_check = self._shell("test", "-f", cert_file, "&&", "echo", "exists")
            if "exists" in out_check:
                self._record("proxy_ca", True, f"mitmproxy CA found at {cert_file}")
                return
            self._record("proxy_ca", False, f"mitmproxy CA not found at {cert_file}")
            return

        out, rc = self._shell("ls", certs_dir)
        cert_count = len(out.strip().split("\n")) if out.strip() else 0
        subject_check, _ = self._shell(
            "for f in " + certs_dir + "/*.0; do "
            "openssl x509 -in $f -noout -subject 2>/dev/null; done"
        )
        if "mitmproxy" in subject_check.lower():
            self._record("proxy_ca", True, "mitmproxy CA found in system trust store")
        else:
            self._record("proxy_ca", False,
                         f"mitmproxy CA not detected in {certs_dir} ({cert_count} certs present)")

    def check_app_installed(self) -> None:
        out, rc = self._shell("pm", "path", self.package)
        if rc == 0 and out.startswith("package:"):
            apk_path = out.split("package:", 1)[1].strip()
            self._record("app_installed", True, f"{self.package} at {apk_path}")
        else:
            self._record("app_installed", False,
                         f"Package {self.package} not installed (rc={rc}, output: {out[:100]})")

    def summary(self) -> dict[str, Any]:
        return {
            "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in self.checks],
            "all_passed": all(c.passed for c in self.checks),
        }
