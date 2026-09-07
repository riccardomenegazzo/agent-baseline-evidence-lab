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
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, [f"manifest.sha256.json cannot be parsed: {exc}"]
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


def verify_bundle(root: Path, *, expected_manifest_sha256: str | None = None, expected_trace_head: str | None = None) -> tuple[bool, list[str], dict[str, Any]]:
    """Verify manifest, trace chain, and the run anchors recorded in assessment.json.

    Optional expected hashes provide an external trust anchor (for example, a CI log or
    ticket). Without one, the bundle is tamper-evident against accidental/local mutation
    but is not cryptographically signed against an attacker able to rewrite every file.
    """
    from .trace import read_trace, verify_trace

    errors: list[str] = []
    manifest_ok, manifest_errors = verify_manifest(root)
    errors.extend(f"manifest: {item}" for item in manifest_errors)

    trace_path = root / "trace" / "events.ndjson"
    trace_ok, trace_errors = verify_trace(trace_path)
    errors.extend(f"trace: {item}" for item in trace_errors)
    events = read_trace(trace_path) if trace_path.exists() else []
    observed_head = str(events[-1].get("event_hash", "")) if events else ""

    assessment_path = root / "assessment.json"
    assessment: dict[str, Any] = {}
    if not assessment_path.exists():
        errors.append("assessment.json is missing")
    else:
        try:
            loaded = json.loads(assessment_path.read_text(encoding="utf-8"))
            assessment = loaded if isinstance(loaded, dict) else {}
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"assessment.json cannot be parsed: {exc}")

    metadata = assessment.get("metadata", {}) if isinstance(assessment, dict) else {}
    recorded_head = str(metadata.get("trace_head_sha256", ""))
    recorded_count = metadata.get("trace_event_count")
    if recorded_head and observed_head and recorded_head != observed_head:
        errors.append("trace head does not match assessment.json metadata")
    if recorded_count is not None and recorded_count != len(events):
        errors.append(f"trace event count mismatch: assessment={recorded_count}, observed={len(events)}")

    manifest_path = root / "manifest.sha256.json"
    observed_manifest_hash = sha256_file(manifest_path) if manifest_path.exists() else ""
    if expected_manifest_sha256 and observed_manifest_hash != expected_manifest_sha256:
        errors.append("manifest hash does not match external expected value")
    if expected_trace_head and observed_head != expected_trace_head:
        errors.append("trace head does not match external expected value")

    summary = {
        "manifest_verified": manifest_ok,
        "trace_verified": trace_ok,
        "manifest_sha256": observed_manifest_hash,
        "trace_head_sha256": observed_head,
        "trace_event_count": len(events),
        "external_manifest_anchor_checked": bool(expected_manifest_sha256),
        "external_trace_anchor_checked": bool(expected_trace_head),
    }
    return not errors, errors, summary
