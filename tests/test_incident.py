from __future__ import annotations

import json
from pathlib import Path

from agent_baseline_lab.evidence import EvidenceStore
from agent_baseline_lab.incident import build_incident_bundle, verify_incident_bundle
from agent_baseline_lab.trace import TraceLedger


def _assessment_bundle(root: Path) -> Path:
    evidence = root / "evidence" / "abl-test"
    trace = TraceLedger(evidence / "trace" / "events.ndjson", "abl-test")
    trace.append("assessment.started", actor="lab", action="assess")
    trace.append("assessment.completed", actor="lab", action="finish")
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "assessment.json").write_text(
        json.dumps(
            {
                "run_id": "abl-test",
                "metadata": {
                    "trace_head_sha256": trace.head_hash,
                    "trace_event_count": trace.sequence,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    EvidenceStore(evidence).finalize_manifest()
    return evidence


def test_incident_bundle_preserves_verified_assessment(tmp_path: Path) -> None:
    assessment = _assessment_bundle(tmp_path)
    summary = build_incident_bundle(assessment, output_root=tmp_path / "incidents")
    root = Path(summary.root)
    ok, errors, verification = verify_incident_bundle(root)
    assert ok is True
    assert errors == []
    assert summary.source_count == 1
    assert verification["file_count"] >= 3


def test_incident_bundle_detects_post_collection_mutation(tmp_path: Path) -> None:
    assessment = _assessment_bundle(tmp_path)
    summary = build_incident_bundle(assessment, output_root=tmp_path / "incidents")
    root = Path(summary.root)
    incident_json = root / "incident.json"
    incident_json.write_text(incident_json.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    ok, errors, _ = verify_incident_bundle(root)
    assert ok is False
    assert any("hash mismatch" in error for error in errors)
