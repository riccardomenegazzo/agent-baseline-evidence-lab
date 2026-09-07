from __future__ import annotations

import hashlib
import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import yaml

from .catalog import CONTROLS

DEFAULT_URL = "https://raw.githubusercontent.com/agentbaseline/agentbaseline/main/whitepaper/controls.yaml"


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
        "url": url,
        "fetched_at": datetime.now(UTC).isoformat(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "version": parsed.get("version"),
        "status": parsed.get("status"),
        "control_count": len(ids),
        "drift": drift,
    }
    (cache_dir / "baseline.lock.json").write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    return lock
