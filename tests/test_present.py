import json
import os
from pathlib import Path

import pytest

from agent_baseline_lab import present
from agent_baseline_lab.evidence import sha256_file
from agent_baseline_lab.signing import generate_keypair, sign_file
from agent_baseline_lab.trust_handoff import create_handoff_pack


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
    _write(trust_dir / "trusted-artifact.portable.json", json.dumps({
        "overall_status": "DRY_RUN" if dry_run else "VERIFIED",
        "scout_status": "NOT_RUN" if dry_run else "PASS",
    }))
    _write(trust_dir / "customer-decision.portable.json", json.dumps({
        "assessment_run_id": run_id, "decision": "CONDITIONAL",
    }))
    if not dry_run:
        _write(trust_dir / "agent-artifact-lineage.json", "{}")
    private_key = public_key.with_name("attestation-private.json")
    if not public_key.exists():
        generate_keypair(private_key, public_key)
    sources = [
        ("customer-trust-flow-html", trust_dir / "customer-trust-flow.html", "flow.html"),
        ("customer-decision-html", trust_dir / "customer-decision.portable.html", "decision.html"),
        ("customer-decision", trust_dir / "customer-decision.portable.json", "decision.json"),
        ("trusted-artifact", trust_dir / "trusted-artifact.portable.json", "trusted.json"),
        ("public-verification-key", public_key, "public.json"),
    ]
    if not dry_run:
        lineage = trust_dir / "agent-artifact-lineage.json"
        lineage_sig = lineage.with_suffix(".ed25519.json")
        sign_file(lineage, private_key, lineage_sig)
        sources.extend([
            ("agent-artifact-lineage", lineage, "lineage.json"),
            ("agent-artifact-lineage-signature", lineage_sig, "lineage.ed25519.json"),
        ])
    create_handoff_pack(root, run_id=run_id, output_path=handoff, dry_run=dry_run, sources=sources)
    sign_file(handoff, private_key, signature)

    summary = {
        "schema_version": 1,
        "handoff_pack_sha256": sha256_file(handoff),
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


def test_presentation_selects_small_verified_artifact_set(tmp_path: Path):
    run_id = _fixture(tmp_path)

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


def test_presentation_prefers_live_run_over_newer_dry_run(tmp_path: Path):
    live_run = _fixture(tmp_path, run_id="abl-live", dry_run=False)
    dry_run = _fixture(tmp_path, run_id="abl-dry", dry_run=True)
    dry_summary = tmp_path / "reports" / f"{dry_run}.customer-trust-flow.json"
    newer = dry_summary.stat().st_mtime + 10
    os.utime(dry_summary, (newer, newer))

    summary = present.build_presentation(tmp_path)

    assert summary.run_id == live_run
    assert summary.dry_run is False


def test_presentation_can_select_exact_run(tmp_path: Path):
    _fixture(tmp_path, run_id="abl-live", dry_run=False)
    dry_run = _fixture(tmp_path, run_id="abl-dry", dry_run=True)

    summary = present.build_presentation(tmp_path, run_id=dry_run)

    assert summary.run_id == dry_run
    assert summary.dry_run is True
    assert "lineage" not in summary.artifacts


def test_presentation_fails_when_required_artifact_is_missing(tmp_path: Path):
    run_id = _fixture(tmp_path)
    (tmp_path / "reports" / f"{run_id}.trust" / "customer-trust-flow.html").unlink()

    with pytest.raises(ValueError, match="presentation artifacts are missing"):
        present.build_presentation(tmp_path)



@pytest.mark.parametrize("filename", [
    "customer-trust-flow.html", "customer-decision.portable.html",
    "trusted-artifact.portable.json", "agent-artifact-lineage.json",
])
def test_presentation_rejects_changed_external_artifact(tmp_path: Path, filename: str):
    run_id = _fixture(tmp_path)
    _write(tmp_path / "reports" / f"{run_id}.trust" / filename, "tampered")
    with pytest.raises(ValueError, match="differs from signed handoff"):
        present.build_presentation(tmp_path)


@pytest.mark.parametrize(("field", "value"), [
    ("dry_run", True), ("dry_run", "false"), ("decision", "EVIDENCE_READY"),
    ("overall_status", "EVIDENCE_READY"), ("trusted_artifact_status", "FAILED"),
    ("scout_status", "NOT_RUN"), ("lineage_verified", False),
    ("handoff_pack_sha256", "0" * 64), ("schema_version", 2),
])
def test_presentation_rejects_changed_summary(tmp_path: Path, field: str, value):
    run_id = _fixture(tmp_path)
    path = tmp_path / "reports" / f"{run_id}.customer-trust-flow.json"
    payload = json.loads(path.read_text())
    payload[field] = value
    _write(path, json.dumps(payload))
    with pytest.raises(ValueError):
        present.build_presentation(tmp_path)


def test_presentation_rejects_swapped_valid_handoff(tmp_path: Path):
    run_id = _fixture(tmp_path, run_id="abl-first")
    other = _fixture(tmp_path, run_id="abl-other")
    path = tmp_path / "reports" / f"{run_id}.customer-trust-flow.json"
    payload = json.loads(path.read_text())
    donor = json.loads((tmp_path / "reports" / f"{other}.customer-trust-flow.json").read_text())
    for field in ("handoff_pack", "handoff_signature", "handoff_pack_sha256"):
        payload[field] = donor[field]
    _write(path, json.dumps(payload))
    with pytest.raises(ValueError, match="different assessment run"):
        present.build_presentation(tmp_path, run_id=run_id)


def test_presentation_rejects_tampered_handoff_signature(tmp_path: Path):
    run_id = _fixture(tmp_path)
    path = tmp_path / "reports" / f"{run_id}.customer-trust-handoff.zip.ed25519.json"
    payload = json.loads(path.read_text())
    payload["subject_sha256"] = "0" * 64
    _write(path, json.dumps(payload))
    with pytest.raises(ValueError, match="signature verification failed"):
        present.build_presentation(tmp_path)


def test_presentation_rejects_path_traversal(tmp_path: Path):
    with pytest.raises(ValueError, match="invalid assessment run ID"):
        present.build_presentation(tmp_path, run_id="../../abl-outside")


def test_presentation_rejects_artifact_symlink_outside_root(tmp_path: Path):
    root = tmp_path / "project"
    run_id = _fixture(root)
    artifact = root / "reports" / f"{run_id}.trust" / "customer-trust-flow.html"
    outside = tmp_path / "outside.html"
    outside.write_bytes(artifact.read_bytes())
    artifact.unlink()
    artifact.symlink_to(outside)
    with pytest.raises(ValueError, match="inside project root"):
        present.build_presentation(root)
