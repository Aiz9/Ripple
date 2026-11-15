"""Core data model: Finding, Evidence, RunContext, scope enforcement."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    BUSINESS_LOGIC = "business_logic"
    CVE = "cve"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    HYPOTHESIS = "hypothesis"


class Reachability(str, Enum):
    CONFIRMED = "confirmed"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    id: str = field(default_factory=lambda: f"FIND-{uuid.uuid4().hex[:8].upper()}")
    title: str = ""
    masvs: str = ""
    mastg_id: str = ""
    cwe: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: Severity = Severity.INFO
    category: Category = Category.STATIC
    confidence: Confidence = Confidence.HYPOTHESIS
    reachability: Reachability = Reachability.UNKNOWN
    evidence: list[str] = field(default_factory=list)
    repro_steps: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    feed_timestamps: dict[str, str] = field(default_factory=dict)
    verified: bool = False
    description: str = ""
    remediation: str = ""
    agent: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        d["confidence"] = self.confidence.value
        d["reachability"] = self.reachability.value
        return d


@dataclass
class AgentError:
    agent: str
    error: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    fatal: bool = False


@dataclass
class RunContext:
    run_id: str = field(default_factory=lambda: f"run-{uuid.uuid4().hex[:12]}")
    apk_path: str = ""
    apk_sha256: str = ""
    package_name: str = ""
    device_serial: str = ""
    scope: Scope | None = None
    out_dir: str = ""
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = field(default_factory=list)
    errors: list[AgentError] = field(default_factory=list)
    kill_reason: str = ""
    killed: bool = False
    untested: list[str] = field(default_factory=list)

    def results_dir(self) -> Path:
        p = Path(self.out_dir) / self.run_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    def evidence_dir(self) -> Path:
        p = self.results_dir() / "evidence"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def add_finding(self, f: Finding) -> None:
        if not f.evidence and not f.repro_steps:
            self.errors.append(AgentError(
                agent=f.agent,
                error=f"Finding '{f.title}' rejected: no evidence or repro steps",
            ))
            return
        self.findings.append(f)

    def add_error(self, agent: str, error: str, fatal: bool = False) -> None:
        self.errors.append(AgentError(agent=agent, error=error, fatal=fatal))


class ScopeError(Exception):
    pass


@dataclass
class Scope:
    packages: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    allow_destructive: bool = False
    race_concurrency_cap: int = 5
    description: str = ""

    @classmethod
    def from_file(cls, path: str) -> Scope:
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(
            packages=data.get("packages", []),
            hosts=data.get("hosts", []),
            allow_destructive=data.get("allow_destructive", False),
            race_concurrency_cap=data.get("race_concurrency_cap", 5),
            description=data.get("description", ""),
        )

    def check_package(self, pkg: str) -> None:
        if pkg not in self.packages:
            raise ScopeError(
                f"Package '{pkg}' is not in scope. "
                f"Allowed packages: {self.packages}. "
                f"Add it to scope.yaml to proceed."
            )

    def check_host(self, host: str) -> bool:
        if not self.hosts:
            return True
        host = host.lower().strip()
        for allowed in self.hosts:
            allowed = allowed.lower().strip()
            if host == allowed or host.endswith("." + allowed):
                return True
        return False


def apk_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)
