"""Static analysis agent: decompile, manifest checks, source scanning."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from vapt.agents.base import BaseAgent
from vapt.core import Finding, Category, Severity, Confidence, Reachability

NS = {"android": "http://schemas.android.com/apk/res/android"}


def _attr(el: ET.Element, name: str) -> str:
    return el.get(f"{{{NS['android']}}}{name}", "")


class StaticAgent(BaseAgent):
    name = "static"
    step_budget = 300
    time_budget = 1200.0

    def __init__(self, ctx, kill_switch, config=None):
        super().__init__(ctx, kill_switch, config)
        self._apktool_dir: str = ""
        self._jadx_dir: str = ""
        self._manifest: ET.Element | None = None
        self._source_root: str = ""
        self._package: str = ""

    # ------------------------------------------------------------------
    # entry
    # ------------------------------------------------------------------

    def execute(self) -> list[Finding]:
        findings: list[Finding] = []
        tmp = tempfile.mkdtemp(prefix="vapt_static_")
        try:
            self._decompile(tmp)
            self.step()
            findings.extend(self._check_manifest())
            self.step()
            findings.extend(self._scan_sources())
            self.step()
            findings.extend(self._run_semgrep())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return findings

    # ------------------------------------------------------------------
    # decompilation
    # ------------------------------------------------------------------

    def _decompile(self, tmp: str) -> None:
        apk = self.ctx.apk_path
        self._apktool_dir = os.path.join(tmp, "apktool")
        self._jadx_dir = os.path.join(tmp, "jadx")

        if shutil.which("apktool"):
            self.log.info("Running apktool …")
            subprocess.run(
                ["apktool", "d", "-f", "-o", self._apktool_dir, apk],
                capture_output=True, timeout=300,
            )
        else:
            self.log.warning("apktool not found; manifest checks rely on aapt2")

        if shutil.which("jadx"):
            self.log.info("Running jadx …")
            subprocess.run(
                ["jadx", "-q", "--no-res", "-d", self._jadx_dir, apk],
                capture_output=True, timeout=480,
            )
            self._source_root = os.path.join(self._jadx_dir, "sources")
        else:
            self.log.warning("jadx not found; source scanning disabled")

        manifest_path = os.path.join(self._apktool_dir, "AndroidManifest.xml")
        if os.path.isfile(manifest_path):
            tree = ET.parse(manifest_path)
            self._manifest = tree.getroot()
            self._package = self._manifest.get("package", "")

    # ------------------------------------------------------------------
    # manifest checks
    # ------------------------------------------------------------------

    def _check_manifest(self) -> list[Finding]:
        if self._manifest is None:
            self.ctx.untested.append("Manifest checks skipped — decompilation failed")
            return []

        findings: list[Finding] = []
        findings.extend(self._check_debuggable())
        self.step()
        findings.extend(self._check_allow_backup())
        self.step()
        findings.extend(self._check_cleartext())
        self.step()
        findings.extend(self._check_exported_components())
        self.step()
        findings.extend(self._check_task_hijacking())
        self.step()
        findings.extend(self._check_custom_permissions())
        return findings

    def _app_el(self) -> ET.Element | None:
        if self._manifest is None:
            return None
        return self._manifest.find("application")

    def _check_debuggable(self) -> list[Finding]:
        app = self._app_el()
        if app is None:
            return []
        if _attr(app, "debuggable") == "true":
            return [Finding(
                title="Application is debuggable",
                masvs="MASVS-RESILIENCE-1",
                mastg_id="MASTG-TEST-0038",
                cwe="CWE-489",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                severity=Severity.HIGH,
                category=Category.STATIC,
                confidence=Confidence.CONFIRMED,
                evidence=["AndroidManifest.xml: android:debuggable=\"true\""],
                repro_steps=[
                    "1. Decode the APK with apktool.",
                    "2. Open AndroidManifest.xml.",
                    "3. Confirm android:debuggable=\"true\" in <application>.",
                    "4. Attach a debugger (e.g. jdb) to the running app via adb.",
                ],
                description="The application has the debuggable flag set, allowing anyone to attach a debugger, inspect memory, and alter control flow at runtime.",
                remediation="Set android:debuggable=\"false\" in the release build.",
            )]
        return []

    def _check_allow_backup(self) -> list[Finding]:
        app = self._app_el()
        if app is None:
            return []
        val = _attr(app, "allowBackup")
        if val == "true" or (val == "" and not _attr(app, "fullBackupContent")):
            return [Finding(
                title="Application allows backup",
                masvs="MASVS-STORAGE-2",
                mastg_id="MASTG-TEST-0038",
                cwe="CWE-530",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                severity=Severity.MEDIUM,
                category=Category.STATIC,
                confidence=Confidence.CONFIRMED,
                evidence=["AndroidManifest.xml: android:allowBackup is true or unset"],
                repro_steps=[
                    "1. Connect a device/emulator via adb.",
                    "2. Run: adb backup -apk <package>",
                    "3. Unpack the resulting .ab and inspect private files.",
                ],
                description="The application data can be extracted through adb backup.",
                remediation="Set android:allowBackup=\"false\" or use android:fullBackupContent with strict rules.",
            )]
        return []

    def _check_cleartext(self) -> list[Finding]:
        app = self._app_el()
        if app is None:
            return []
        if _attr(app, "usesCleartextTraffic") == "true":
            return [Finding(
                title="Cleartext traffic permitted",
                masvs="MASVS-NETWORK-1",
                mastg_id="MASTG-TEST-0019",
                cwe="CWE-319",
                cvss_score=5.9,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                severity=Severity.MEDIUM,
                category=Category.STATIC,
                confidence=Confidence.CONFIRMED,
                evidence=["AndroidManifest.xml: android:usesCleartextTraffic=\"true\""],
                repro_steps=[
                    "1. Decode the APK with apktool.",
                    "2. Open AndroidManifest.xml.",
                    "3. Verify android:usesCleartextTraffic=\"true\".",
                    "4. Use mitmproxy/Wireshark to observe unencrypted HTTP traffic.",
                ],
                description="The application explicitly allows cleartext (HTTP) network traffic.",
                remediation="Set android:usesCleartextTraffic=\"false\" and use a network security config that restricts to HTTPS.",
            )]
        return []

    def _check_exported_components(self) -> list[Finding]:
        findings: list[Finding] = []
        for kind in ("activity", "receiver", "service", "provider"):
            for comp in self._manifest.iter(kind):
                self.step()
                name = _attr(comp, "name")
                exported = _attr(comp, "exported")
                perm = _attr(comp, "permission") or _attr(comp, "readPermission") or _attr(comp, "writePermission")

                has_intent_filter = comp.find("intent-filter") is not None
                is_exported = exported == "true" or (exported == "" and has_intent_filter)

                if not is_exported:
                    continue
                if perm:
                    continue

                sev = Severity.HIGH if kind in ("provider", "service") else Severity.MEDIUM
                score = 7.5 if kind in ("provider", "service") else 5.3

                findings.append(Finding(
                    title=f"Exported {kind} without permission: {name}",
                    masvs="MASVS-PLATFORM-1",
                    mastg_id="MASTG-TEST-0024",
                    cwe="CWE-926",
                    cvss_score=score,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    severity=sev,
                    category=Category.STATIC,
                    confidence=Confidence.CONFIRMED,
                    evidence=[f"AndroidManifest.xml: <{kind} android:name=\"{name}\" android:exported=\"true\"> with no permission"],
                    repro_steps=[
                        f"1. Identify the exported {kind}: {name}",
                        f"2. Start the component from adb: adb shell am start -n {self._package}/{name}" if kind == "activity" else f"2. Interact via adb or drozer.",
                        "3. Observe that no permission is required.",
                    ],
                    description=f"The {kind} '{name}' is exported and accessible to any app on the device without a required permission.",
                    remediation=f"Set android:exported=\"false\" or add an android:permission attribute to the {kind}.",
                ))
        return findings

    def _check_task_hijacking(self) -> list[Finding]:
        findings: list[Finding] = []
        for act in self._manifest.iter("activity"):
            self.step()
            exported = _attr(act, "exported")
            has_intent_filter = act.find("intent-filter") is not None
            if not (exported == "true" or (exported == "" and has_intent_filter)):
                continue
            affinity = _attr(act, "taskAffinity")
            if affinity and affinity != self._package:
                name = _attr(act, "name")
                findings.append(Finding(
                    title=f"Task hijacking risk: {name}",
                    masvs="MASVS-PLATFORM-2",
                    mastg_id="MASTG-TEST-0025",
                    cwe="CWE-1021",
                    cvss_score=5.0,
                    cvss_vector="CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    severity=Severity.MEDIUM,
                    category=Category.STATIC,
                    confidence=Confidence.SUSPECTED,
                    evidence=[f"AndroidManifest.xml: {name} has taskAffinity=\"{affinity}\""],
                    repro_steps=[
                        f"1. Note activity {name} with taskAffinity=\"{affinity}\".",
                        "2. Create a PoC app with the same taskAffinity.",
                        "3. Launch the PoC; the target activity may appear in the PoC task.",
                    ],
                    description=f"Activity '{name}' uses a non-default taskAffinity, enabling potential task-hijacking (StrandHogg-like attacks).",
                    remediation="Remove explicit taskAffinity or set it to the package name.",
                ))
        return findings

    def _check_custom_permissions(self) -> list[Finding]:
        findings: list[Finding] = []
        for perm in self._manifest.iter("permission"):
            self.step()
            name = _attr(perm, "name")
            level = _attr(perm, "protectionLevel")
            if level and level not in ("signature", "signatureOrSystem"):
                findings.append(Finding(
                    title=f"Custom permission with weak protection: {name}",
                    masvs="MASVS-PLATFORM-1",
                    mastg_id="MASTG-TEST-0024",
                    cwe="CWE-732",
                    cvss_score=5.0,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    severity=Severity.MEDIUM,
                    category=Category.STATIC,
                    confidence=Confidence.CONFIRMED,
                    evidence=[f"AndroidManifest.xml: <permission android:name=\"{name}\" android:protectionLevel=\"{level}\">"],
                    repro_steps=[
                        f"1. Note custom permission {name} with protectionLevel=\"{level}\".",
                        "2. Any app can request this permission and access protected components.",
                    ],
                    description=f"Custom permission '{name}' uses protectionLevel=\"{level}\" — any third-party app can request it.",
                    remediation="Use protectionLevel=\"signature\" for custom permissions.",
                ))
        return findings

    # ------------------------------------------------------------------
    # source scanning (regex)
    # ------------------------------------------------------------------

    def _scan_sources(self) -> list[Finding]:
        if not self._source_root or not os.path.isdir(self._source_root):
            self.ctx.untested.append("Source code scanning skipped — jadx decompilation unavailable")
            return []

        findings: list[Finding] = []
        for root, _dirs, files in os.walk(self._source_root):
            for fname in files:
                self.step()
                if not fname.endswith(".java") and not fname.endswith(".kt"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    content = Path(fpath).read_text(errors="replace")
                except OSError:
                    continue
                rel = os.path.relpath(fpath, self._source_root)
                findings.extend(self._check_hardcoded_secrets(content, rel))
                findings.extend(self._check_insecure_crypto(content, rel))
                findings.extend(self._check_webview(content, rel))
                findings.extend(self._check_insecure_storage(content, rel))
                findings.extend(self._check_logging(content, rel))
                findings.extend(self._check_sql_injection(content, rel))
                findings.extend(self._check_insecure_random(content, rel))
        return findings

    # --- secret patterns ---

    _SECRET_PATTERNS: list[tuple[re.Pattern, str, str]] = [
        (re.compile(r'(?:api[_-]?key|apikey)\s*=\s*"([^"]{8,})"', re.I), "Hardcoded API key", "CWE-798"),
        (re.compile(r'(?:password|passwd|pwd)\s*=\s*"([^"]{4,})"', re.I), "Hardcoded password", "CWE-798"),
        (re.compile(r'(?:secret|private[_-]?key)\s*=\s*"([^"]{8,})"', re.I), "Hardcoded secret/key", "CWE-798"),
        (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), "Embedded private key", "CWE-321"),
        (re.compile(r'AIza[0-9A-Za-z_-]{35}'), "Google API key", "CWE-798"),
        (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS access key", "CWE-798"),
        (re.compile(r'(?:firebase|firestore).*(?:://[^\s"]+)', re.I), "Firebase/Firestore URL", "CWE-798"),
    ]

    def _check_hardcoded_secrets(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, desc, cwe in self._SECRET_PATTERNS:
            for m in pattern.finditer(content):
                line_no = content[:m.start()].count("\n") + 1
                snippet = content[max(0, m.start() - 40):m.end() + 40].strip()
                findings.append(Finding(
                    title=f"{desc} in {rel_path}",
                    masvs="MASVS-STORAGE-1",
                    mastg_id="MASTG-TEST-0044",
                    cwe=cwe,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    severity=Severity.HIGH,
                    category=Category.STATIC,
                    confidence=Confidence.CONFIRMED,
                    evidence=[f"{rel_path}:{line_no}: {snippet}"],
                    repro_steps=[
                        f"1. Decompile the APK with jadx.",
                        f"2. Open {rel_path} at line {line_no}.",
                        f"3. Observe the hardcoded credential.",
                    ],
                    description=f"A hardcoded credential ({desc}) was found in the source code.",
                    remediation="Store secrets in the Android Keystore or fetch them from a secure backend at runtime.",
                ))
        return findings

    # --- crypto patterns ---

    _CRYPTO_PATTERNS: list[tuple[re.Pattern, str, str, str, float]] = [
        (re.compile(r'Cipher\.getInstance\(\s*"[^"]*ECB[^"]*"\s*\)'), "ECB mode cipher",
         "CWE-327", "MASVS-CRYPTO-1", 7.5),
        (re.compile(r'Cipher\.getInstance\(\s*"DES[/"]\s*'), "DES cipher",
         "CWE-327", "MASVS-CRYPTO-1", 7.5),
        (re.compile(r'MessageDigest\.getInstance\(\s*"MD5"\s*\)'), "MD5 hash",
         "CWE-328", "MASVS-CRYPTO-1", 5.3),
        (re.compile(r'MessageDigest\.getInstance\(\s*"SHA-?1"\s*\)'), "SHA-1 hash",
         "CWE-328", "MASVS-CRYPTO-1", 5.3),
        (re.compile(r'(?:new\s+)?IvParameterSpec\(\s*(?:new\s+byte\[\]\s*\{[^}]*\}|"[^"]*"\.getBytes)', re.I),
         "Static IV", "CWE-329", "MASVS-CRYPTO-1", 7.5),
        (re.compile(r'(?:new\s+)?SecretKeySpec\(\s*"[^"]*"\.getBytes'), "Hardcoded crypto key",
         "CWE-321", "MASVS-CRYPTO-1", 9.1),
    ]

    def _check_insecure_crypto(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, desc, cwe, masvs, score in self._CRYPTO_PATTERNS:
            for m in pattern.finditer(content):
                line_no = content[:m.start()].count("\n") + 1
                snippet = m.group(0)[:120]
                sev = Severity.CRITICAL if score >= 9.0 else Severity.HIGH if score >= 7.0 else Severity.MEDIUM
                findings.append(Finding(
                    title=f"{desc} in {rel_path}",
                    masvs=masvs,
                    mastg_id="MASTG-TEST-0014",
                    cwe=cwe,
                    cvss_score=score,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    severity=sev,
                    category=Category.STATIC,
                    confidence=Confidence.CONFIRMED,
                    evidence=[f"{rel_path}:{line_no}: {snippet}"],
                    repro_steps=[
                        "1. Decompile the APK with jadx.",
                        f"2. Open {rel_path} at line {line_no}.",
                        f"3. Observe the use of {desc}.",
                    ],
                    description=f"Insecure cryptographic construction ({desc}) found in source.",
                    remediation="Use AES-GCM with a random IV and keys stored in the Android Keystore.",
                ))
        return findings

    # --- webview patterns ---

    _WEBVIEW_PATTERNS: list[tuple[re.Pattern, str, str, float]] = [
        (re.compile(r'\.setJavaScriptEnabled\(\s*true\s*\)'), "JavaScript enabled in WebView",
         "CWE-749", 5.3),
        (re.compile(r'\.setAllowFileAccess\(\s*true\s*\)'), "File access in WebView",
         "CWE-200", 5.3),
        (re.compile(r'\.setAllowUniversalAccessFromFileURLs\(\s*true\s*\)'), "Universal file access in WebView",
         "CWE-200", 7.5),
        (re.compile(r'\.addJavascriptInterface\('), "JavaScript interface exposed",
         "CWE-749", 7.5),
    ]

    def _check_webview(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, desc, cwe, score in self._WEBVIEW_PATTERNS:
            for m in pattern.finditer(content):
                line_no = content[:m.start()].count("\n") + 1
                snippet = content[max(0, m.start() - 20):m.end() + 60].strip().replace("\n", " ")[:150]
                sev = Severity.HIGH if score >= 7.0 else Severity.MEDIUM
                findings.append(Finding(
                    title=f"{desc} in {rel_path}",
                    masvs="MASVS-PLATFORM-2",
                    mastg_id="MASTG-TEST-0032",
                    cwe=cwe,
                    cvss_score=score,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    severity=sev,
                    category=Category.STATIC,
                    confidence=Confidence.CONFIRMED,
                    evidence=[f"{rel_path}:{line_no}: {snippet}"],
                    repro_steps=[
                        "1. Decompile the APK with jadx.",
                        f"2. Open {rel_path} at line {line_no}.",
                        f"3. Observe {desc}.",
                    ],
                    description=f"WebView misconfiguration: {desc}.",
                    remediation="Disable JavaScript/file access unless strictly required, and never expose JS interfaces to untrusted content.",
                ))
        return findings

    # --- insecure storage ---

    _STORAGE_PATTERNS: list[tuple[re.Pattern, str, str, float]] = [
        (re.compile(r'MODE_WORLD_READABLE'), "World-readable file mode", "CWE-276", 7.5),
        (re.compile(r'MODE_WORLD_WRITEABLE'), "World-writeable file mode", "CWE-276", 7.5),
        (re.compile(r'getExternal(?:Storage|FilesDir|CacheDir)\b'), "External storage usage", "CWE-922", 5.3),
        (re.compile(r'openFileOutput\(\s*"[^"]*"\s*,\s*(?:1|2|3)\s*\)'), "Insecure file creation mode", "CWE-276", 7.5),
    ]

    def _check_insecure_storage(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, desc, cwe, score in self._STORAGE_PATTERNS:
            for m in pattern.finditer(content):
                line_no = content[:m.start()].count("\n") + 1
                snippet = content[max(0, m.start() - 20):m.end() + 40].strip().replace("\n", " ")[:150]
                sev = Severity.HIGH if score >= 7.0 else Severity.MEDIUM
                findings.append(Finding(
                    title=f"{desc} in {rel_path}",
                    masvs="MASVS-STORAGE-2",
                    mastg_id="MASTG-TEST-0001",
                    cwe=cwe,
                    cvss_score=score,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    severity=sev,
                    category=Category.STATIC,
                    confidence=Confidence.CONFIRMED,
                    evidence=[f"{rel_path}:{line_no}: {snippet}"],
                    repro_steps=[
                        "1. Decompile the APK with jadx.",
                        f"2. Open {rel_path} at line {line_no}.",
                        f"3. Observe {desc}.",
                        "4. On a rooted device, check file permissions or external storage for leaked data.",
                    ],
                    description=f"Insecure local storage: {desc}.",
                    remediation="Use MODE_PRIVATE for internal files and avoid external storage for sensitive data.",
                ))
        return findings

    # --- logging ---

    _LOG_PATTERN = re.compile(
        r'Log\.\w+\([^)]*(?:password|token|secret|key|session|cookie|auth|cred|pin|otp|ssn|credit)(?:\w*)[^)]*\)',
        re.I,
    )

    def _check_logging(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in self._LOG_PATTERN.finditer(content):
            line_no = content[:m.start()].count("\n") + 1
            snippet = m.group(0)[:150]
            findings.append(Finding(
                title=f"Sensitive data logged in {rel_path}",
                masvs="MASVS-STORAGE-1",
                mastg_id="MASTG-TEST-0003",
                cwe="CWE-532",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                severity=Severity.MEDIUM,
                category=Category.STATIC,
                confidence=Confidence.SUSPECTED,
                evidence=[f"{rel_path}:{line_no}: {snippet}"],
                repro_steps=[
                    "1. Decompile the APK with jadx.",
                    f"2. Open {rel_path} at line {line_no}.",
                    "3. Run the app and capture logcat output.",
                    "4. Check for the sensitive value in the log.",
                ],
                description="A logging call appears to include sensitive data (password, token, etc.).",
                remediation="Remove or guard sensitive logging behind BuildConfig.DEBUG.",
            ))
        return findings

    # --- SQL injection ---

    _SQL_PATTERN = re.compile(
        r'\.(?:rawQuery|execSQL)\(\s*(?:"[^"]*"\s*\+|[a-zA-Z_]\w*\s*\+)',
    )

    def _check_sql_injection(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for m in self._SQL_PATTERN.finditer(content):
            line_no = content[:m.start()].count("\n") + 1
            snippet = content[max(0, m.start() - 10):m.end() + 80].strip().replace("\n", " ")[:180]
            findings.append(Finding(
                title=f"Potential SQL injection in {rel_path}",
                masvs="MASVS-STORAGE-2",
                mastg_id="MASTG-TEST-0005",
                cwe="CWE-89",
                cvss_score=8.6,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                severity=Severity.HIGH,
                category=Category.STATIC,
                confidence=Confidence.SUSPECTED,
                evidence=[f"{rel_path}:{line_no}: {snippet}"],
                repro_steps=[
                    "1. Decompile the APK with jadx.",
                    f"2. Open {rel_path} at line {line_no}.",
                    "3. Observe string concatenation in rawQuery/execSQL.",
                    "4. Supply a malicious input to the concatenated parameter via the exposed entry point.",
                ],
                description="SQL query built with string concatenation, allowing injection.",
                remediation="Use parameterised queries (selectionArgs) instead of concatenation.",
            ))
        return findings

    # --- insecure random ---

    _RANDOM_PATTERN = re.compile(r'new\s+(?:java\.util\.)?Random\b')

    def _check_insecure_random(self, content: str, rel_path: str) -> list[Finding]:
        if not self._RANDOM_PATTERN.search(content):
            return []
        security_context = re.search(
            r'(?:token|nonce|salt|key|iv|otp|seed|challenge|random)',
            content, re.I,
        )
        if not security_context:
            return []
        m = self._RANDOM_PATTERN.search(content)
        if m is None:
            return []
        line_no = content[:m.start()].count("\n") + 1
        return [Finding(
            title=f"java.util.Random in security context in {rel_path}",
            masvs="MASVS-CRYPTO-1",
            mastg_id="MASTG-TEST-0016",
            cwe="CWE-330",
            cvss_score=5.9,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            severity=Severity.MEDIUM,
            category=Category.STATIC,
            confidence=Confidence.SUSPECTED,
            evidence=[f"{rel_path}:{line_no}: java.util.Random used near security-sensitive code"],
            repro_steps=[
                "1. Decompile the APK with jadx.",
                f"2. Open {rel_path} at line {line_no}.",
                "3. Observe java.util.Random used in a security-relevant context.",
            ],
            description="java.util.Random is not cryptographically secure and should not be used for tokens, keys, or nonces.",
            remediation="Use java.security.SecureRandom for all security-critical randomness.",
        )]

    # ------------------------------------------------------------------
    # semgrep (optional)
    # ------------------------------------------------------------------

    def _run_semgrep(self) -> list[Finding]:
        if not self._source_root or not os.path.isdir(self._source_root):
            return []
        if not shutil.which("semgrep"):
            self.log.info("semgrep not installed; skipping rule-based scan")
            return []

        rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "semgrep")
        if not os.path.isdir(rules_dir) or not os.listdir(rules_dir):
            self.log.info("No custom semgrep rules found; skipping")
            return []

        self.log.info("Running semgrep …")
        try:
            result = subprocess.run(
                ["semgrep", "--config", rules_dir, "--json", "--quiet", self._source_root],
                capture_output=True, text=True, timeout=300,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        if result.returncode not in (0, 1):
            return []

        findings: list[Finding] = []
        try:
            data = __import__("json").loads(result.stdout)
        except Exception:
            return []

        for hit in data.get("results", []):
            self.step()
            msg = hit.get("extra", {}).get("message", hit.get("check_id", "semgrep finding"))
            sev_raw = hit.get("extra", {}).get("severity", "WARNING").upper()
            sev_map = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
            rel_path = os.path.relpath(hit.get("path", ""), self._source_root)
            line = hit.get("start", {}).get("line", 0)
            snippet = hit.get("extra", {}).get("lines", "")[:200]
            meta = hit.get("extra", {}).get("metadata", {})
            findings.append(Finding(
                title=f"[semgrep] {msg}",
                masvs=meta.get("masvs", ""),
                cwe=meta.get("cwe", ""),
                cvss_score=float(meta.get("cvss", 5.0)),
                severity=sev_map.get(sev_raw, Severity.MEDIUM),
                category=Category.STATIC,
                confidence=Confidence.SUSPECTED,
                evidence=[f"{rel_path}:{line}: {snippet}"],
                repro_steps=[
                    f"1. Decompile the APK with jadx.",
                    f"2. Open {rel_path} at line {line}.",
                    f"3. Observe the pattern flagged by semgrep rule {hit.get('check_id', '')}.",
                ],
                description=msg,
            ))
        return findings
