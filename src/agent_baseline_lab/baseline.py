from __future__ import annotations

import hashlib
import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .catalog import CONTROLS

DEFAULT_URL = "https://raw.githubusercontent.com/agentbaseline/agentbaseline/main/whitepaper/controls.yaml"


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sync(url: str, cache_dir: Path) -> dict:
    cache_dir.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=15) as response:
        raw = response.read()
    parsed = yaml.safe_load(raw)
    ids = [c.get("id") for c in parsed.get("controls", [])]
    expected = [c.id for c in CONTROLS]
    if set(ids) != set(expected):
        missing = sorted(set(expected) - set(ids))
        added = sorted(set(ids) - set(expected))
        drift = {"missing_from_upstream": missing, "new_upstream_ids": added}
    else:
        drift = {"missing_from_upstream": [], "new_upstream_ids": []}
    target = cache_dir / "controls.yaml"
    target.write_bytes(raw)
    lock = {
        "schema_version": 1,
        "url": url,
        "fetched_at": datetime.now(UTC).isoformat(),
        "sha256": _sha256_bytes(raw),
        "version": parsed.get("version"),
        "status": parsed.get("status"),
        "control_count": len(ids),
        "control_ids": sorted(str(item) for item in ids if item),
        "drift": drift,
    }
    (cache_dir / "baseline.lock.json").write_text(
        json.dumps(lock, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return lock


def verify_lock(cache_dir: str | Path) -> tuple[bool, list[str], dict[str, Any]]:
    root = Path(cache_dir)
    controls_path = root / "controls.yaml"
    lock_path = root / "baseline.lock.json"
    errors: list[str] = []
    if not controls_path.exists():
        return False, ["controls.yaml is missing"], {}
    if not lock_path.exists():
        return False, ["baseline.lock.json is missing"], {}
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        parsed = yaml.safe_load(controls_path.read_bytes())
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        return False, [f"baseline lock/source cannot be parsed: {exc}"], {}
    if lock.get("schema_version", 1) != 1:
        errors.append("unsupported baseline lock schema_version")

    raw = controls_path.read_bytes()
    observed_sha = _sha256_bytes(raw)
    if str(lock.get("sha256", "")) != observed_sha:
        errors.append("controls.yaml digest does not match baseline.lock.json")

    controls = parsed.get("controls", []) if isinstance(parsed, dict) else []
    ids = sorted(
        str(control.get("id"))
        for control in controls
        if isinstance(control, dict) and control.get("id")
    )
    if int(lock.get("control_count", -1)) != len(ids):
        errors.append("control_count does not match controls.yaml")
    locked_ids = lock.get("control_ids")
    if locked_ids is not None and sorted(map(str, locked_ids)) != ids:
        errors.append("control_ids do not match controls.yaml")
    if lock.get("version") != parsed.get("version"):
        errors.append("baseline version does not match controls.yaml")
    if lock.get("status") != parsed.get("status"):
        errors.append("baseline status does not match controls.yaml")

    expected_ids = sorted(control.id for control in CONTROLS)
    observed_drift = {
        "missing_from_upstream": sorted(set(expected_ids) - set(ids)),
        "new_upstream_ids": sorted(set(ids) - set(expected_ids)),
    }
    if lock.get("drift") != observed_drift:
        errors.append("recorded baseline drift does not match current catalogue comparison")

    summary = {
        "source_sha256": observed_sha,
        "lock_sha256": _sha256_bytes(lock_path.read_bytes()),
        "control_count": len(ids),
        "version": parsed.get("version"),
        "status": parsed.get("status"),
        "drift": observed_drift,
        "valid": not errors,
    }
    return not errors, errors, summary
