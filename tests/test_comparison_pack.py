from __future__ import annotations

import json
import zipfile
from pathlib import Path

from agent_baseline_lab.comparison_pack import (
    create_comparison_pack,
    verify_comparison_pack,
)
from agent_baseline_lab.evidence import EvidenceStore
from agent_baseline_lab.models import Result, RunReport, Status
from agent_baseline_lab.provenance import write_run_attestation
from agent_baseline_lab.signing import generate_keypair
from agent_baseline_lab.trace import TraceLedger


def _run(root: Path, run_id: str, status: Status) -> Path:
    evidence = root / "evidence" / run_id
    evidence.mkdir(parents=True)
    ledger = TraceLedger(evidence / "trace" / "events.ndjson", run_id)
    ledger.append("assessment.started", actor="lab", action="assess")
    ledger.append("assessment.completed", actor="lab", action="finalize")
    assessment = {
        "run_id": run_id,
        "baseline_version": "1.0-draft",
        "config_path": "examples/agent.yaml",
        "metadata": {
            "agent_id": "customer-agent",
            "trace_head_sha256": ledger.head_hash,
            "trace_event_count": ledger.sequence,
        },
        "results": [
            {
                "control_id": "C-01",
                "status": status.value,
                "summary": "test",
                "details": [],
                "evidence": [],
                "evaluator": "test",
            }
        ],
    }
    (evidence / "assessment.json").write_text(
        json.dumps(assessment, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest = EvidenceStore(evidence).finalize_manifest()

    reports = root / "reports"
    reports.mkdir(exist_ok=True)
    report = RunReport(
        run_id=run_id,
        started_at="2026-09-08T00:00:00+00:00",
        completed_at="2026-09-08T00:01:00+00:00",
        baseline_version="1.0-draft",
        config_path="examples/agent.yaml",
        results=[Result(control_id="C-01", status=status, summary="test")],
        metadata={
            "agent_id": "customer-agent",
            "trace_head_sha256": ledger.head_hash,
            "trace_event_count": ledger.sequence,
        },
    )
    (reports / f"{run_id}.json").write_text(
        json.dumps(report.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )
    write_run_attestation(
        report,
        manifest_path=manifest,
        context={},
        output_path=reports / f"{run_id}.attestation.json",
    )
    return evidence


def _keys(root: Path) -> tuple[Path, Path]:
    private = root / ".abl" / "keys" / "attestation-private.json"
    public = root / ".abl" / "keys" / "attestation-public.json"
    generate_keypair(private, public)
    return private, public


def test_comparison_pack_verifies_offline_with_external_signature(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    before = _run(root, "abl-before", Status.PARTIAL)
    after = _run(root, "abl-after", Status.PASS)
    _, public = _keys(root)
    output = root / "reports" / "comparison.zip"

    pack, signature, summary = create_comparison_pack(
        root,
        before,
        after,
        output_path=output,
    )
    ok, errors, verification = verify_comparison_pack(
        pack,
        signature_path=signature,
        public_key_path=public,
    )

    assert ok is True, errors
    assert summary.before_run_id == "abl-before"
    assert summary.after_run_id == "abl-after"
    assert verification["external_pack_signature_checked"] is True
    assert verification["delta"]["change_counts"] == {"control-improvement": 1}
    assert verification["pack_signature"]["signature_valid"] is True

    with zipfile.ZipFile(pack) as zf:
        names = set(zf.namelist())
        assert "before/customer-evidence-pack.zip" in names
        assert "after/customer-evidence-pack.zip" in names
        assert "comparison/governance-delta.json" in names
        assert "trust/attestation-public.json" in names
        assert not any(name.endswith("attestation-private.json") for name in names)
        delta = json.loads(zf.read("comparison/governance-delta.json"))
        assert delta["change_counts"] == {"control-improvement": 1}


def test_comparison_pack_detects_nested_pack_tampering(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    before = _run(root, "abl-before", Status.FAIL)
    after = _run(root, "abl-after", Status.PASS)
    _keys(root)
    original = root / "reports" / "comparison.zip"
    create_comparison_pack(root, before, after, output_path=original)

    tampered = root / "reports" / "comparison-tampered.zip"
    with zipfile.ZipFile(original, "r") as source, zipfile.ZipFile(tampered, "w") as target:
        for name in source.namelist():
            data = source.read(name)
            if name == "before/customer-evidence-pack.zip":
                data += b"tampered"
            target.writestr(name, data)

    ok, errors, _ = verify_comparison_pack(tampered)
    assert ok is False
    assert any("digest mismatch" in error for error in errors)


def test_comparison_pack_requires_local_signing_keypair(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    before = _run(root, "abl-before", Status.PARTIAL)
    after = _run(root, "abl-after", Status.PASS)

    try:
        create_comparison_pack(
            root,
            before,
            after,
            output_path=root / "reports" / "comparison.zip",
        )
    except ValueError as exc:
        assert "signing-keygen" in str(exc)
    else:
        raise AssertionError("comparison pack creation should require a signing keypair")
