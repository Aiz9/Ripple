"""CVE agent: extracts third-party libraries, queries vulnerability databases, prioritises with KEV/EPSS."""

from __future__ import annotations

import json
import logging
import os
import re
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from vapt.agents.base import BaseAgent
from vapt.core import (
    Category,
    Confidence,
    Finding,
    Reachability,
    RunContext,
    Severity,
)
from vapt.kill_switch import KillSwitch

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known Maven-group → package-name mappings for common Android libraries
# ---------------------------------------------------------------------------
_KNOWN_LIBS: dict[str, str] = {
    "com.squareup.okhttp3": "okhttp",
    "com.squareup.okhttp": "okhttp",
    "com.squareup.retrofit2": "retrofit",
    "com.squareup.retrofit": "retrofit",
    "com.google.code.gson": "gson",
    "com.google.gson": "gson",
    "com.google.firebase": "firebase-android-sdk",
    "com.google.android.gms": "play-services",
    "io.reactivex.rxjava2": "rxjava",
    "io.reactivex.rxjava3": "rxjava",
    "org.apache.commons": "commons",
    "org.apache.httpcomponents": "httpclient",
    "com.fasterxml.jackson": "jackson",
    "com.github.bumptech.glide": "glide",
    "com.squareup.picasso": "picasso",
    "org.greenrobot": "eventbus",
    "com.facebook.fresco": "fresco",
    "com.airbnb.android": "lottie",
}

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[-.]\w+)?)")
_GRADLE_DEP_RE = re.compile(
    r"""(?:implementation|api|compile|classpath)\s*[\s(]['"]([^'"]+):([^'"]+):([^'"]+)['"]""",
    re.IGNORECASE,
)
_POM_DEP_RE = re.compile(
    r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
    re.DOTALL,
)


@dataclass
class LibInfo:
    group: str
    artifact: str
    version: str
    source: str  # where we found it


# ---------------------------------------------------------------------------
# Helper: rate-limited HTTP client
# ---------------------------------------------------------------------------
class _RateLimitedClient:
    """Thin wrapper that enforces a minimum interval between requests."""

    def __init__(self, client: httpx.Client, min_interval: float = 0.5):
        self._client = client
        self._min_interval = min_interval
        self._last_request: float = 0.0

    def _wait(self) -> None:
        now = time.monotonic()
        gap = self._min_interval - (now - self._last_request)
        if gap > 0:
            time.sleep(gap)
        self._last_request = time.monotonic()

    def get(self, url: str, **kw: Any) -> httpx.Response:
        self._wait()
        return self._client.get(url, **kw)

    def post(self, url: str, **kw: Any) -> httpx.Response:
        self._wait()
        return self._client.post(url, **kw)


# ---------------------------------------------------------------------------
# CVE Agent
# ---------------------------------------------------------------------------
class CVEAgent(BaseAgent):
    name = "cve"
    step_budget = 100
    time_budget = 600.0

    def __init__(self, ctx: RunContext, kill_switch: KillSwitch, config: dict | None = None):
        super().__init__(ctx, kill_switch, config)
        self._libs: list[LibInfo] = []
        self._kev_cves: set[str] = set()
        self._epss_cache: dict[str, float] = {}
        self._feed_ts: dict[str, str] = {}
        self._source_root: str = ""
        self._http = _RateLimitedClient(
            httpx.Client(timeout=30, follow_redirects=True),
            min_interval=0.6,
        )

    # ------------------------------------------------------------------
    # Library extraction
    # ------------------------------------------------------------------

    def _extract_from_apk(self) -> None:
        """Pull library hints directly from the APK zip entries."""
        self.step()
        apk = self.ctx.apk_path
        if not apk or not os.path.isfile(apk):
            return
        try:
            with zipfile.ZipFile(apk, "r") as zf:
                for name in zf.namelist():
                    # .so files often encode the library name
                    if name.startswith("lib/") and name.endswith(".so"):
                        base = os.path.basename(name).removeprefix("lib").removesuffix(".so")
                        m = _VERSION_RE.search(base)
                        if m:
                            self._libs.append(LibInfo("native", base, m.group(1), f"APK:{name}"))

                    # META-INF pom.properties / MANIFEST.MF
                    if "META-INF" in name and (name.endswith("pom.properties") or name.endswith("pom.xml")):
                        try:
                            content = zf.read(name).decode("utf-8", errors="replace")
                        except Exception:
                            continue
                        if name.endswith("pom.properties"):
                            props: dict[str, str] = {}
                            for line in content.splitlines():
                                if "=" in line:
                                    k, _, v = line.partition("=")
                                    props[k.strip()] = v.strip()
                            g = props.get("groupId", "")
                            a = props.get("artifactId", "")
                            v = props.get("version", "")
                            if g and a and v:
                                self._libs.append(LibInfo(g, a, v, f"APK:{name}"))
                        elif name.endswith("pom.xml"):
                            for gm, am, vm in _POM_DEP_RE.findall(content):
                                self._libs.append(LibInfo(gm, am, vm, f"APK:{name}"))
        except (zipfile.BadZipFile, OSError) as exc:
            self.log.warning("Cannot open APK as zip: %s", exc)

    def _extract_from_sources(self, source_root: str) -> None:
        """Scan decompiled sources for Gradle/Maven dependency declarations and version strings."""
        self.step()
        root = Path(source_root)
        if not root.is_dir():
            return
        for fpath in root.rglob("*.gradle*"):
            self.step()
            try:
                text = fpath.read_text(errors="replace")
            except OSError:
                continue
            for g, a, v in _GRADLE_DEP_RE.findall(text):
                self._libs.append(LibInfo(g, a, v, f"gradle:{fpath.name}"))

        for fpath in root.rglob("*.xml"):
            if fpath.name not in ("pom.xml", "build.xml"):
                continue
            self.step()
            try:
                text = fpath.read_text(errors="replace")
            except OSError:
                continue
            for g, a, v in _POM_DEP_RE.findall(text):
                self._libs.append(LibInfo(g, a, v, f"pom:{fpath.name}"))

    def _extract_from_class_patterns(self, source_root: str) -> None:
        """Check for known package directory patterns."""
        self.step()
        root = Path(source_root) / "sources"
        if not root.is_dir():
            return
        for group_prefix, lib_name in _KNOWN_LIBS.items():
            pkg_dir = root / group_prefix.replace(".", "/")
            if pkg_dir.is_dir():
                version = self._guess_version_in_dir(pkg_dir)
                if version:
                    self._libs.append(LibInfo(group_prefix, lib_name, version, "class-pattern"))

    @staticmethod
    def _guess_version_in_dir(d: Path) -> str:
        """Heuristic: look for a version string in the first few Java files under *d*."""
        for fpath in list(d.rglob("*.java"))[:20]:
            try:
                text = fpath.read_text(errors="replace")
            except OSError:
                continue
            m = re.search(r'VERSION\s*=\s*["\'](\d+\.\d+[^"\']*)["\']', text)
            if m:
                return m.group(1)
        return ""

    def _dedup_libs(self) -> None:
        seen: set[str] = set()
        unique: list[LibInfo] = []
        for lib in self._libs:
            key = f"{lib.group}:{lib.artifact}:{lib.version}"
            if key not in seen:
                seen.add(key)
                unique.append(lib)
        self._libs = unique

    # ------------------------------------------------------------------
    # Vulnerability database queries
    # ------------------------------------------------------------------

    def _query_osv(self, lib: LibInfo) -> list[dict]:
        self.step()
        ecosystem = "Maven" if lib.source != "native" else "Android"
        pkg_name = f"{lib.group}:{lib.artifact}" if lib.group != "native" else lib.artifact
        payload = {
            "version": lib.version,
            "package": {"name": pkg_name, "ecosystem": ecosystem},
        }
        try:
            resp = self._http.post("https://api.osv.dev/v1/query", json=payload)
            self._feed_ts["osv"] = datetime.now(timezone.utc).isoformat()
            if resp.status_code == 200:
                return resp.json().get("vulns", [])
        except Exception as exc:
            self.log.warning("OSV query failed for %s: %s", pkg_name, exc)
        return []

    def _query_nvd(self, keyword: str) -> list[dict]:
        self.step()
        nvd_key = self.config.get("nvd_api_key", os.environ.get("NVD_API_KEY", ""))
        headers: dict[str, str] = {}
        if nvd_key:
            headers["apiKey"] = nvd_key
        params = {"keywordSearch": keyword, "resultsPerPage": "20"}
        try:
            resp = self._http.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
                headers=headers,
            )
            self._feed_ts["nvd"] = datetime.now(timezone.utc).isoformat()
            if resp.status_code == 200:
                return resp.json().get("vulnerabilities", [])
        except Exception as exc:
            self.log.warning("NVD query failed for %s: %s", keyword, exc)
        return []

    def _query_ghsa(self, ecosystem: str, pkg: str) -> list[dict]:
        self.step()
        gh_token = self.config.get("github_token", os.environ.get("GITHUB_TOKEN", ""))
        if not gh_token:
            return []
        query = """
        query($ecosystem:SecurityAdvisoryEcosystem,$pkg:String!){
          securityVulnerabilities(first:20,ecosystem:$ecosystem,package:$pkg){
            nodes{
              advisory{ghsaId summary severity publishedAt
                identifiers{type value}
                cvss{score vectorString}
              }
              vulnerableVersionRange
              firstPatchedVersion{identifier}
            }
          }
        }"""
        variables = {"ecosystem": ecosystem, "pkg": pkg}
        try:
            resp = self._http.post(
                "https://api.github.com/graphql",
                json={"query": query, "variables": variables},
                headers={"Authorization": f"bearer {gh_token}"},
            )
            self._feed_ts["ghsa"] = datetime.now(timezone.utc).isoformat()
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return data.get("securityVulnerabilities", {}).get("nodes", [])
        except Exception as exc:
            self.log.warning("GHSA query failed for %s: %s", pkg, exc)
        return []

    def _load_kev(self) -> None:
        self.step()
        try:
            resp = self._http.get(
                "https://www.cisa.gov/sites/default/files/feeds/known-exploited-vulnerabilities.json"
            )
            self._feed_ts["cisa_kev"] = datetime.now(timezone.utc).isoformat()
            if resp.status_code == 200:
                for vuln in resp.json().get("vulnerabilities", []):
                    cve_id = vuln.get("cveID", "")
                    if cve_id:
                        self._kev_cves.add(cve_id)
                self.log.info("Loaded %d CISA KEV entries", len(self._kev_cves))
        except Exception as exc:
            self.log.warning("CISA KEV fetch failed: %s", exc)

    def _get_epss(self, cve_ids: list[str]) -> dict[str, float]:
        if not cve_ids:
            return {}
        self.step()
        batch = ",".join(cve_ids[:100])
        try:
            resp = self._http.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": batch},
            )
            self._feed_ts["epss"] = datetime.now(timezone.utc).isoformat()
            if resp.status_code == 200:
                for entry in resp.json().get("data", []):
                    cid = entry.get("cve", "")
                    score = float(entry.get("epss", 0))
                    self._epss_cache[cid] = score
        except Exception as exc:
            self.log.warning("EPSS fetch failed: %s", exc)
        return self._epss_cache

    # ------------------------------------------------------------------
    # Reachability heuristic
    # ------------------------------------------------------------------

    def _assess_reachability(self, lib: LibInfo) -> Reachability:
        """Basic reachability: if the library's package dir is present in sources we mark UNKNOWN;
        if we can find direct import statements we mark CONFIRMED; otherwise UNREACHABLE."""
        root = Path(self._source_root) / "sources" if self._source_root else None
        if not root or not root.is_dir():
            return Reachability.UNKNOWN

        pkg_dir = root / lib.group.replace(".", "/")
        if not pkg_dir.is_dir():
            return Reachability.UNREACHABLE

        import_pattern = re.compile(rf"import\s+{re.escape(lib.group)}\.", re.MULTILINE)
        app_pkg = self.ctx.package_name.replace(".", "/")
        app_dir = root / app_pkg
        if not app_dir.is_dir():
            return Reachability.UNKNOWN

        for java in list(app_dir.rglob("*.java"))[:200]:
            try:
                text = java.read_text(errors="replace")
            except OSError:
                continue
            if import_pattern.search(text):
                return Reachability.CONFIRMED

        return Reachability.UNKNOWN

    # ------------------------------------------------------------------
    # Finding construction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _cvss_to_severity(score: float) -> Severity:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score >= 0.1:
            return Severity.LOW
        return Severity.INFO

    def _build_finding_from_osv(self, vuln: dict, lib: LibInfo) -> Finding | None:
        cve_ids = [
            alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-")
        ]
        osv_id = vuln.get("id", "")
        if not cve_ids and not osv_id:
            return None

        severity_block = vuln.get("database_specific", {}).get("severity") or vuln.get("severity", [])
        cvss_score = 0.0
        cvss_vector = ""
        cwe = ""
        if isinstance(severity_block, list):
            for s in severity_block:
                if s.get("type") == "CVSS_V3":
                    cvss_vector = s.get("score", "")
        # attempt extraction from references
        for ref in vuln.get("references", []):
            url = ref.get("url", "")
            if "nvd.nist.gov" in url:
                break

        # try to parse CVSS from affected
        for aff in vuln.get("affected", []):
            eco_sev = aff.get("database_specific", {}).get("cvss", {})
            if eco_sev:
                cvss_score = float(eco_sev.get("score", cvss_score))
                cvss_vector = eco_sev.get("vectorString", cvss_vector)

        kev = any(c in self._kev_cves for c in cve_ids)
        epss = max((self._epss_cache.get(c, 0.0) for c in cve_ids), default=0.0)
        reach = self._assess_reachability(lib)

        title = vuln.get("summary", f"Vulnerability in {lib.group}:{lib.artifact}")
        if len(title) > 200:
            title = title[:197] + "..."

        return Finding(
            title=title,
            masvs="MASVS-CODE-4",
            mastg_id="MASTG-TEST-0025",
            cwe=cwe or "CWE-1395",
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=self._cvss_to_severity(cvss_score) if cvss_score else Severity.MEDIUM,
            category=Category.CVE,
            confidence=Confidence.CONFIRMED if reach == Reachability.CONFIRMED else Confidence.SUSPECTED,
            reachability=reach,
            evidence=[
                f"Library: {lib.group}:{lib.artifact}:{lib.version} (source: {lib.source})",
                f"Advisory: {osv_id}",
                f"CISA KEV: {'YES' if kev else 'no'}",
                f"EPSS: {epss:.4f}",
            ],
            repro_steps=[
                f"1. Decompile APK and locate dependency {lib.group}:{lib.artifact} version {lib.version}",
                f"2. Cross-reference with {osv_id} / {', '.join(cve_ids) or 'N/A'}",
                "3. Verify the vulnerable code path is reachable from app code",
            ],
            cve_ids=cve_ids or [osv_id],
            feed_timestamps=dict(self._feed_ts),
            description=vuln.get("details", ""),
            remediation=self._remediation_from_osv(vuln, lib),
            raw_data={"kev": kev, "epss": epss, "lib": f"{lib.group}:{lib.artifact}:{lib.version}"},
        )

    @staticmethod
    def _remediation_from_osv(vuln: dict, lib: LibInfo) -> str:
        for aff in vuln.get("affected", []):
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    fixed = ev.get("fixed")
                    if fixed:
                        return f"Upgrade {lib.artifact} to >= {fixed}"
        return f"Review {lib.artifact} for available patches"

    def _build_finding_from_nvd(self, vuln_wrapper: dict, lib: LibInfo) -> Finding | None:
        cve_data = vuln_wrapper.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return None

        metrics = cve_data.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = ""
        for v3 in metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", []):
            cd = v3.get("cvssData", {})
            cvss_score = cd.get("baseScore", 0.0)
            cvss_vector = cd.get("vectorString", "")
            break

        cwe = ""
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwe = desc["value"]
                    break

        descs = cve_data.get("descriptions", [])
        summary = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        kev = cve_id in self._kev_cves
        epss = self._epss_cache.get(cve_id, 0.0)
        reach = self._assess_reachability(lib)

        title = f"{cve_id}: {summary[:120]}" if summary else cve_id

        return Finding(
            title=title,
            masvs="MASVS-CODE-4",
            mastg_id="MASTG-TEST-0025",
            cwe=cwe or "CWE-1395",
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=self._cvss_to_severity(cvss_score) if cvss_score else Severity.MEDIUM,
            category=Category.CVE,
            confidence=Confidence.CONFIRMED if reach == Reachability.CONFIRMED else Confidence.SUSPECTED,
            reachability=reach,
            evidence=[
                f"Library: {lib.group}:{lib.artifact}:{lib.version} (source: {lib.source})",
                f"CVE: {cve_id}",
                f"CVSS: {cvss_score} ({cvss_vector})",
                f"CISA KEV: {'YES' if kev else 'no'}",
                f"EPSS: {epss:.4f}",
            ],
            repro_steps=[
                f"1. Identify dependency {lib.group}:{lib.artifact} version {lib.version}",
                f"2. Confirm vulnerability {cve_id} applies to this version",
                "3. Assess reachability of the vulnerable code path",
            ],
            cve_ids=[cve_id],
            feed_timestamps=dict(self._feed_ts),
            description=summary,
            remediation=f"Upgrade {lib.artifact} to a patched version",
            raw_data={"kev": kev, "epss": epss, "lib": f"{lib.group}:{lib.artifact}:{lib.version}"},
        )

    def _build_finding_from_ghsa(self, node: dict, lib: LibInfo) -> Finding | None:
        adv = node.get("advisory", {})
        ghsa_id = adv.get("ghsaId", "")
        if not ghsa_id:
            return None

        cve_ids = [
            ident["value"]
            for ident in adv.get("identifiers", [])
            if ident.get("type") == "CVE"
        ]

        cvss_data = adv.get("cvss", {})
        cvss_score = cvss_data.get("score", 0.0)
        cvss_vector = cvss_data.get("vectorString", "")
        summary = adv.get("summary", "")
        ghsa_sev = adv.get("severity", "").upper()

        sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM, "LOW": Severity.LOW}
        severity = sev_map.get(ghsa_sev, self._cvss_to_severity(cvss_score))

        kev = any(c in self._kev_cves for c in cve_ids)
        epss = max((self._epss_cache.get(c, 0.0) for c in cve_ids), default=0.0)
        reach = self._assess_reachability(lib)
        patched = node.get("firstPatchedVersion", {})
        fix_ver = patched.get("identifier", "") if patched else ""

        title = f"{ghsa_id}: {summary[:120]}" if summary else ghsa_id
        return Finding(
            title=title,
            masvs="MASVS-CODE-4",
            mastg_id="MASTG-TEST-0025",
            cwe="CWE-1395",
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            category=Category.CVE,
            confidence=Confidence.CONFIRMED if reach == Reachability.CONFIRMED else Confidence.SUSPECTED,
            reachability=reach,
            evidence=[
                f"Library: {lib.group}:{lib.artifact}:{lib.version} (source: {lib.source})",
                f"GHSA: {ghsa_id}",
                f"Vulnerable range: {node.get('vulnerableVersionRange', 'unknown')}",
                f"CISA KEV: {'YES' if kev else 'no'}",
                f"EPSS: {epss:.4f}",
            ],
            repro_steps=[
                f"1. Identify dependency {lib.group}:{lib.artifact} version {lib.version}",
                f"2. Advisory {ghsa_id} covers range {node.get('vulnerableVersionRange', '?')}",
                f"3. Upgrade to {fix_ver}" if fix_ver else "3. Review advisory for mitigation",
            ],
            cve_ids=cve_ids or [ghsa_id],
            feed_timestamps=dict(self._feed_ts),
            description=summary,
            remediation=f"Upgrade {lib.artifact} to >= {fix_ver}" if fix_ver else f"Review {ghsa_id} for patches",
            raw_data={"kev": kev, "epss": epss, "lib": f"{lib.group}:{lib.artifact}:{lib.version}"},
        )

    # ------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------

    def execute(self) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Extract libraries
        self._source_root = self.config.get("source_root", "")
        self._extract_from_apk()
        if self._source_root:
            self._extract_from_sources(self._source_root)
            self._extract_from_class_patterns(self._source_root)
        self._dedup_libs()
        self.log.info("Discovered %d unique libraries", len(self._libs))

        if not self._libs:
            self.ctx.untested.append("CVE: no third-party libraries detected")
            return []

        # 2. Load CISA KEV catalog once
        self._load_kev()

        # 3. Collect all CVE IDs we'll encounter (for batch EPSS later)
        all_cve_ids: list[str] = []

        # 4. Query per library
        seen_ids: set[str] = set()
        raw_findings: list[tuple[Finding, LibInfo]] = []

        for lib in self._libs:
            self.step()
            pkg_name = f"{lib.group}:{lib.artifact}" if lib.group != "native" else lib.artifact

            # OSV
            for vuln in self._query_osv(lib):
                f = self._build_finding_from_osv(vuln, lib)
                if f and f.id not in seen_ids:
                    seen_ids.add(f.id)
                    all_cve_ids.extend(f.cve_ids)
                    raw_findings.append((f, lib))

            # NVD (use artifact name as keyword; NVD free-text)
            for vuln_w in self._query_nvd(f"{lib.artifact} {lib.version}"):
                f = self._build_finding_from_nvd(vuln_w, lib)
                if f and not any(c in seen_ids for c in f.cve_ids):
                    for c in f.cve_ids:
                        seen_ids.add(c)
                    all_cve_ids.extend(f.cve_ids)
                    raw_findings.append((f, lib))

            # GHSA
            for node in self._query_ghsa("MAVEN", pkg_name):
                f = self._build_finding_from_ghsa(node, lib)
                if f and not any(c in seen_ids for c in f.cve_ids):
                    for c in f.cve_ids:
                        seen_ids.add(c)
                    all_cve_ids.extend(f.cve_ids)
                    raw_findings.append((f, lib))

        # 5. Batch EPSS lookup
        if all_cve_ids:
            unique_cves = list(set(c for c in all_cve_ids if c.startswith("CVE-")))
            self._get_epss(unique_cves)

        # 6. Enrich findings with EPSS, finalise
        for f, lib in raw_findings:
            self.step()
            epss = max((self._epss_cache.get(c, 0.0) for c in f.cve_ids), default=0.0)
            kev = any(c in self._kev_cves for c in f.cve_ids)
            f.raw_data["epss"] = epss
            f.raw_data["kev"] = kev
            # boost severity for KEV entries
            if kev and f.severity not in (Severity.CRITICAL,):
                f.severity = Severity.CRITICAL
            f.feed_timestamps = dict(self._feed_ts)
            findings.append(f)

        self.log.info("CVE agent produced %d findings from %d libraries", len(findings), len(self._libs))
        return findings
