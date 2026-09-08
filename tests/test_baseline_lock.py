from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from agent_baseline_lab.baseline_lock import (
    sign_baseline_lock,
    verify_baseline_lock,
    verify_signed_baseline_lock,
)
from agent_baseline_lab.signing import generate_keypair


def _cache(tmp_path: Path) -> Path:
    cache = tmp_path / "baseline-cache"
    cache.mkdir()
    controls = cache / "controls.yaml"
    controls.write_text("version: test\ncontrols:\n  - id: DIS-01\n", encoding="utf-8")
    digest = hashlib.sha256(controls.read_bytes()).hexdigest()
    (cache / "baseline.lock.json").write_text(
        json.dumps(
            {
                "url": "https://example.invalid/controls.yaml",
                "sha256": digest,
                "version": "test",
                "control_count": 1,
                "drift": {"missing_from_upstream": [], "new_upstream_ids": []},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return cache


def test_baseline_lock_detects_cached_source_mutation(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    ok, errors, _ = verify_baseline_lock(cache)
    assert ok is True
    (cache / "controls.yaml").write_text("version: changed\ncontrols: []\n", encoding="utf-8")
    ok, errors, _ = verify_baseline_lock(cache)
    assert ok is False
    assert any("digest" in error for error in errors)


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen unavailable")
def test_signed_baseline_lock_uses_external_fingerprint(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    private, _, fingerprint = generate_keypair(tmp_path / "signing-key", identity="baseline@example")
    sign_baseline_lock(cache, private_key=private, identity="baseline@example")
    ok, errors, summary = verify_signed_baseline_lock(cache, expected_fingerprint=fingerprint)
    assert ok is True
    assert errors == []
    assert summary["signature"]["external_fingerprint_checked"] is True
