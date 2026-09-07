from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .models import EvidenceItem


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class EvidenceStore:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def write_json(self, relative_path: str, payload: Any, description: str = "") -> EvidenceItem:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return EvidenceItem(
            path=relative_path,
            sha256=sha256_file(path),
            media_type="application/json",
            description=description,
        )

    def write_text(self, relative_path: str, text: str, description: str = "") -> EvidenceItem:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return EvidenceItem(
            path=relative_path,
            sha256=sha256_file(path),
            media_type="text/plain",
            description=description,
        )

    def finalize_manifest(self) -> Path:
        entries = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and path.name != "manifest.sha256.json":
                entries.append({
                    "path": str(path.relative_to(self.root)),
                    "sha256": sha256_file(path),
                    "bytes": path.stat().st_size,
                })
        manifest = self.root / "manifest.sha256.json"
        manifest.write_text(json.dumps({"algorithm": "sha256", "files": entries}, indent=2) + "\n")
        return manifest


def verify_manifest(root: Path) -> tuple[bool, list[str]]:
    manifest = root / "manifest.sha256.json"
    if not manifest.exists():
        return False, ["manifest.sha256.json is missing"]
    data = json.loads(manifest.read_text(encoding="utf-8"))
    errors: list[str] = []
    for item in data.get("files", []):
        path = root / item["path"]
        if not path.exists():
            errors.append(f"missing: {item['path']}")
            continue
        observed = sha256_file(path)
        if observed != item["sha256"]:
            errors.append(f"hash mismatch: {item['path']}")
    return not errors, errors
