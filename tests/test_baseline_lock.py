from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

from agent_baseline_lab.baseline import verify_lock
from agent_baseline_lab.catalog import CONTROLS


def _write_fixture(root: Path) -> None:
    controls = {
        "version": "1.0-draft",
        "status": "draft",
        "controls": [{"id": control.id} for control in CONTROLS],
    }
    raw = yaml.safe_dump(controls, sort_keys=False).encode("utf-8")
    (root / "controls.yaml").write_bytes(raw)
    ids = sorted(control.id for control in CONTROLS)
    lock = {
        "schema_version": 1,
        "url": "https://example.invalid/controls.yaml",
        "fetched_at": "2026-09-08T00:00:00+00:00",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "version": "1.0-draft",
        "status": "draft",
        "control_count": len(ids),
        "control_ids": ids,
        "drift": {"missing_from_upstream": [], "new_upstream_ids": []},
    }
    (root / "baseline.lock.json").write_text(
        json.dumps(lock, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_baseline_lock_verifies_and_detects_source_mutation(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    ok, errors, summary = verify_lock(tmp_path)
    assert ok is True
    assert errors == []
    assert summary["valid"] is True

    with (tmp_path / "controls.yaml").open("a", encoding="utf-8") as handle:
        handle.write("# mutated\n")
    mutated_ok, mutated_errors, _ = verify_lock(tmp_path)
    assert mutated_ok is False
    assert any("digest" in error for error in mutated_errors)
