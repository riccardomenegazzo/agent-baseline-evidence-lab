from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_baseline_lab import golden_flow


def _keys(root: Path) -> None:
    keys = root / ".abl" / "keys"
    keys.mkdir(parents=True)
    (keys / "attestation-private.json").write_text("private\n", encoding="utf-8")
    (keys / "attestation-public.json").write_text("public\n", encoding="utf-8")


def test_golden_flow_requires_preexisting_signing_keypair(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="signing-keygen"):
        golden_flow.run_golden_flow(tmp_path, dry_run=True)


def test_live_golden_flow_fails_closed_on_readiness_failure(tmp_path: Path, monkeypatch) -> None:
    _keys(tmp_path)
    monkeypatch.setattr(
        golden_flow,
        "run_readiness",
        lambda *args, **kwargs: SimpleNamespace(
            ready=False,
            checks=[SimpleNamespace(required=True, status="FAIL", name="binary:sbx")],
            to_dict=lambda: {"ready": False},
        ),
    )

    with pytest.raises(ValueError, match="binary:sbx"):
        golden_flow.run_golden_flow(tmp_path, dry_run=False)


def test_live_golden_flow_requires_signed_baseline_lock(tmp_path: Path, monkeypatch) -> None:
    _keys(tmp_path)
    cache = tmp_path / ".cache" / "agentbaseline"
    cache.mkdir(parents=True)
    (cache / "baseline.lock.json").write_text('{"schema_version":1}\n', encoding="utf-8")
    monkeypatch.setattr(
        golden_flow,
        "run_readiness",
        lambda *args, **kwargs: SimpleNamespace(
            ready=True,
            checks=[],
            to_dict=lambda: {"ready": True},
        ),
    )

    with pytest.raises(ValueError, match="baseline-lock-sign"):
        golden_flow.run_golden_flow(tmp_path, dry_run=False)


def test_dry_run_golden_flow_skips_live_readiness_but_signs_handoff(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _keys(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    run_id = "abl-test"
    attestation = reports / f"{run_id}.attestation.json"
    attestation.write_text('{"attestation":true}\n', encoding="utf-8")

    monkeypatch.setattr(
        golden_flow,
        "run_interview_demo",
        lambda *args, **kwargs: SimpleNamespace(
            assessment_run_id=run_id,
            assessment_bundle_verified=True,
            response_link_verified=False,
            quarantine_registered=False,
            incident_bundle_verified=False,
        ),
    )

    def fake_sign(subject, private_key, output):
        Path(output).write_text("signature\n", encoding="utf-8")
        return SimpleNamespace()

    monkeypatch.setattr(golden_flow, "sign_file", fake_sign)
    monkeypatch.setattr(
        golden_flow,
        "verify_signature",
        lambda *args, **kwargs: (True, [], {"signature_valid": True}),
    )
    monkeypatch.setattr(
        golden_flow,
        "run_assurance_suite",
        lambda root: SimpleNamespace(
            assessment_run_id=run_id,
            blocking_failures=0,
            overall_status="PASS",
            to_dict=lambda: {
                "assessment_run_id": run_id,
                "blocking_failures": 0,
                "overall_status": "PASS",
            },
        ),
    )

    def fake_create_pack(root, *, output_path, run_id):
        Path(output_path).write_bytes(b"portable-pack")
        return Path(output_path), SimpleNamespace()

    monkeypatch.setattr(golden_flow, "create_pack", fake_create_pack)
    monkeypatch.setattr(
        golden_flow,
        "verify_pack",
        lambda *args, **kwargs: (True, [], {"valid": True}),
    )

    summary = golden_flow.run_golden_flow(tmp_path, dry_run=True)

    assert summary.dry_run is True
    assert summary.readiness_checked is False
    assert summary.readiness_ready is None
    assert summary.baseline_signature_checked is False
    assert summary.baseline_signature_verified is None
    assert summary.assessment_run_id == run_id
    assert summary.response_link_verified is False
    assert summary.quarantine_registered is False
    assert summary.incident_bundle_verified is False
    assert summary.attestation_signature_verified is True
    assert summary.assurance_blocking_failures == 0
    assert summary.customer_pack == f"reports/{run_id}.customer-evidence-pack.zip"
    assert summary.customer_pack_signature_verified is True
    assert (reports / f"{run_id}.golden-flow.json").is_file()
