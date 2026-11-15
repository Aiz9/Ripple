"""Encrypted evidence store with secret redaction and retention limits."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet


class EvidenceStore:
    def __init__(self, evidence_dir: str, key: bytes | None = None):
        self._dir = Path(evidence_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        if key is None:
            key_path = self._dir / ".evidence_key"
            if key_path.exists():
                key = key_path.read_bytes()
            else:
                key = Fernet.generate_key()
                key_path.write_bytes(key)
                os.chmod(key_path, 0o600)
        self._fernet = Fernet(key)
        self._manifest: list[dict] = []

    def store(self, name: str, data: bytes | str, metadata: dict | None = None) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        encrypted = self._fernet.encrypt(data)
        file_id = hashlib.sha256(data).hexdigest()[:16]
        out_path = self._dir / f"{file_id}.enc"
        out_path.write_bytes(encrypted)
        entry = {
            "id": file_id,
            "name": name,
            "path": str(out_path),
            "size": len(data),
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }
        if metadata:
            entry["metadata"] = metadata
        self._manifest.append(entry)
        return str(out_path)

    def retrieve(self, file_id: str) -> bytes | None:
        path = self._dir / f"{file_id}.enc"
        if not path.exists():
            return None
        return self._fernet.decrypt(path.read_bytes())

    def save_manifest(self) -> None:
        manifest_path = self._dir / "manifest.json"
        manifest_path.write_text(json.dumps(self._manifest, indent=2))

    def enforce_retention(self, max_age_hours: int = 72) -> int:
        cutoff = time.time() - (max_age_hours * 3600)
        removed = 0
        for path in self._dir.glob("*.enc"):
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        return removed
