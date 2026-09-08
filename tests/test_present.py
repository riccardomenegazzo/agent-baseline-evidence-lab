import json
import os
from pathlib import Path

import pytest

from agent_baseline_lab import present


def _write(path: Path, text: str = "fixture") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _fixture(root: Path, *, run_id: str = "abl-20260908-test", dry_run: bool = False) -> str:
    trust_dir = root / "reports" / f"{run_id}.trust"
    handoff = root / "reports" / f"{run_id}.customer-trust-handoff.zip"
    signature = root / "reports" / f"{run_id}.customer-trust-handoff.zip.ed25519.json"
    public_key = root / ".abl" / "keys" / "attestation-public.json"

    _write(trust_dir / "customer-trust-flow.html", "<html>flow</html>")
    _write(trust_dir / "customer-decision.portable.html", "<html>decision</html>")
    _write(trust_dir / "trusted-artifact.portable.json", "{}")
    if not dry_run:
        _write(trust_dir / "agent-artifact-lineage.json", "{}")
    _write(handoff)
    _write(signature, "{}")
    _write(public_key, "{}")

    summary = {
        "assessment_run_id": run_id,
        "dry_run": dry_run,
        "decision": "CONDITIONAL",
        "overall_status": "DRY_RUN" if dry_run else "CONDITIONAL",
        "trusted_artifact_status": "DRY_RUN" if dry_run else "VERIFIED",
        "scout_status": "NOT_RUN" if dry_run else "PASS",
        "lineage_verified": not dry_run,
        "handoff_pack": handoff.relative_to(root).as_posix(),
        "handoff_signature": signature.relative_to(root).as_posix(),
        "public_key": public_key.relative_to(root).as_posix(),
    }
    _write(
        root / "reports" / f"{run_id}.customer-trust-flow.json",
        json.dumps(summary),
    )
    return run_id


def _mock_verifiers(monkeypatch) -> None:
    monkeypatch.setattr(present, "verify_handoff_pack", lambda path: (True, [], {}))
    monkeypatch.setattr(present, "verify_signature", lambda *args, **kwargs: (True, [], {}))


def test_presentation_selects_small_verified_artifact_set(monkeypatch, tmp_path: Path):
    run_id = _fixture(tmp_path)
    _mock_verifiers(monkeypatch)

    summary = present.build_presentation(tmp_path)

    assert summary.run_id == run_id
    assert summary.dry_run is False
    assert summary.handoff_verified is True
    assert summary.handoff_signature_verified is True
    assert summary.lineage_verified is True
    assert set(summary.artifacts) == {
        "flow_html",
        "decision_html",
        "trusted_artifact",
        "handoff",
        "handoff_signature",
        "public_key",
        "lineage",
    }


def test_presentation_prefers_live_run_over_newer_dry_run(monkeypatch, tmp_path: Path):
    live_run = _fixture(tmp_path, run_id="abl-live", dry_run=False)
    dry_run = _fixture(tmp_path, run_id="abl-dry", dry_run=True)
    dry_summary = tmp_path / "reports" / f"{dry_run}.customer-trust-flow.json"
    newer = dry_summary.stat().st_mtime + 10
    os.utime(dry_summary, (newer, newer))
    _mock_verifiers(monkeypatch)

    summary = present.build_presentation(tmp_path)

    assert summary.run_id == live_run
    assert summary.dry_run is False


def test_presentation_can_select_exact_run(monkeypatch, tmp_path: Path):
    _fixture(tmp_path, run_id="abl-live", dry_run=False)
    dry_run = _fixture(tmp_path, run_id="abl-dry", dry_run=True)
    _mock_verifiers(monkeypatch)

    summary = present.build_presentation(tmp_path, run_id=dry_run)

    assert summary.run_id == dry_run
    assert summary.dry_run is True
    assert "lineage" not in summary.artifacts


def test_presentation_fails_when_required_artifact_is_missing(monkeypatch, tmp_path: Path):
    run_id = _fixture(tmp_path)
    (tmp_path / "reports" / f"{run_id}.trust" / "customer-trust-flow.html").unlink()
    _mock_verifiers(monkeypatch)

    with pytest.raises(ValueError, match="presentation artifacts are missing"):
        present.build_presentation(tmp_path)
