import json
from pathlib import Path

from agent_baseline_lab.evidence import EvidenceStore, verify_bundle
from agent_baseline_lab.evidence_matrix import run_verification_matrix
from agent_baseline_lab.trace import TraceLedger


def _bundle(root: Path) -> Path:
    evidence = root / "evidence" / "abl-test"
    store = EvidenceStore(evidence)
    ledger = TraceLedger(evidence / "trace" / "events.ndjson", "abl-test")
    ledger.append(
        "assessment.started",
        actor="lab",
        action="assess",
        task_id="task-1",
        result="started",
    )
    ledger.append(
        "mcp.tool",
        actor="codex",
        action="read",
        target="dhi",
        task_id="task-1",
        result="allowed",
    )
    ledger.append(
        "assessment.completed",
        actor="lab",
        action="finalize",
        task_id="task-1",
        result="completed",
    )
    store.write_json("controls/OBS-06/evidence.json", {"integrity": "sha256"})
    (evidence / "assessment.json").write_text(
        json.dumps(
            {
                "run_id": "abl-test",
                "metadata": {
                    "trace_head_sha256": ledger.head_hash,
                    "trace_event_count": ledger.sequence,
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    store.finalize_manifest()
    ok, errors, _ = verify_bundle(evidence)
    assert ok, errors
    return evidence


def test_verification_matrix_exposes_distinct_trust_boundaries(tmp_path: Path):
    evidence = _bundle(tmp_path)
    output = tmp_path / "matrix.json"
    scenarios, summary = run_verification_matrix(evidence, output_path=output)
    by_id = {item.id: item for item in scenarios}

    assert by_id["single-file-alteration"].alteration_detected_internally is True
    assert by_id["trace-truncation"].alteration_detected_internally is True

    coordinated = by_id["coordinated-rewrite"]
    assert coordinated.internal_verifier_passed is True
    assert coordinated.alteration_detected_internally is False
    assert coordinated.externally_anchored_verifier_passed is False
    assert coordinated.alteration_detected_with_external_anchor is True

    never_emitted = by_id["event-never-emitted"]
    assert never_emitted.internal_verifier_passed is True
    assert never_emitted.externally_anchored_verifier_passed is True
    assert never_emitted.alteration_detected_internally is False
    assert never_emitted.alteration_detected_with_external_anchor is False

    assert summary["scenario_count"] == 4
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["summary"]["source_trace_event_count"] == 3
