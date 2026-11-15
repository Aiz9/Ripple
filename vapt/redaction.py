"""Redact tokens, passwords, and PII before sending to LLM or writing reports."""

from __future__ import annotations

import re

PATTERNS = [
    (re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{4,})', re.I), "PASSWORD"),
    (re.compile(r'(?:token|jwt|bearer|auth|session_id|sessionid|api_key|apikey|secret)\s*[:=]\s*["\']?([^\s"\']{8,})', re.I), "TOKEN"),
    (re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'), "BASE64_BLOB"),
    (re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'), "JWT"),
    (re.compile(r'AIza[0-9A-Za-z_-]{35}'), "GOOGLE_API_KEY"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS_ACCESS_KEY"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), "GITHUB_TOKEN"),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b', re.I), "EMAIL"),
    (re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'), "PHONE"),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "SSN"),
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'), "CREDIT_CARD"),
]


def redact(text: str, replacement: str = "[REDACTED:{kind}]") -> str:
    for pattern, kind in PATTERNS:
        text = pattern.sub(replacement.format(kind=kind), text)
    return text


def redact_dict(data: dict, keys_to_redact: set[str] | None = None) -> dict:
    if keys_to_redact is None:
        keys_to_redact = {
            "password", "passwd", "pwd", "token", "secret",
            "api_key", "apikey", "auth", "authorization",
            "session", "cookie", "csrf", "jwt", "bearer",
        }
    result = {}
    for k, v in data.items():
        if k.lower() in keys_to_redact:
            result[k] = "[REDACTED]"
        elif isinstance(v, dict):
            result[k] = redact_dict(v, keys_to_redact)
        elif isinstance(v, str):
            result[k] = redact(v)
        elif isinstance(v, list):
            result[k] = [redact(str(item)) if isinstance(item, str) else item for item in v]
        else:
            result[k] = v
    return result
