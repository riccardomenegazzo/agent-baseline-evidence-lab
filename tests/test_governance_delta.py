from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_baseline_lab.evidence import EvidenceStore
from agent_baseline_lab.governance_delta import (
    build_delta,
    verify_delta,
    write_delta_html,
    write_delta_json,
)
from agent_baseline_lab.trace import TraceLedger


def _bundle(
    root: Path,
    run_id: str,
    statuses: dict[str, str],
    *,
    baseline: str = "1.0-draft",
    agent_id: str = "customer-agent",
) -> Path:
    evidence = root / run_id
    evidence.mkdir(parents=True)
    ledger = TraceLedger(evidence / "trace" / "events.ndjson", run_id)
    ledger.append("assessment.started", actor="lab", action="assess")
    ledger.append("assessment.completed", actor="lab", action="finalize")
    assessment = {
        "run_id": run_id,
        "baseline_version": baseline,
        "config_path": "examples/agent.yaml",
        "metadata": {
            "agent_id": agent_id,
            "trace_head_sha256": ledger.head_hash,
            "trace_event_count": ledger.sequence,
        },
        "results": [
            {
                "control_id": control_id,
                "status": status,
                "summary": "test",
                "details": [],
                "evidence": [],
                "evaluator": "test",
            }
            for control_id, status in sorted(statuses.items())
        ],
    }
    (evidence / "assessment.json").write_text(
        json.dumps(assessment, indent=2) + "\n",
        encoding="utf-8",
    )
    EvidenceStore(evidence).finalize_manifest()
    return evidence


def test_governance_delta_classifies_evidence_without_security_score(tmp_path: Path) -> None:
    before = _bundle(
        tmp_path,
        "abl-before",
        {
            "C-01": "FAIL",
            "C-02": "MANUAL",
            "C-03": "PASS",
            "C-04": "ERROR",
            "C-05": "PASS",
            "C-06": "N/A",
            "C-07": "PASS",
            "C-08": "PARTIAL",
            "C-09": "PASS",
        },
    )
    after = _bundle(
        tmp_path,
        "abl-after",
        {
            "C-01": "PASS",
            "C-02": "FAIL",
            "C-03": "MANUAL",
            "C-04": "PARTIAL",
            "C-05": "ERROR",
            "C-06": "PASS",
            "C-07": "PARTIAL",
            "C-08": "PASS",
            "C-09": "PASS",
        },
    )

    delta = build_delta(before, after)
    changes = {item.control_id: item.change_type for item in delta.changes}

    assert changes["C-01"] == "control-improvement"
    assert changes["C-02"] == "evidence-gain"
    assert changes["C-03"] == "evidence-loss"
    assert changes["C-04"] == "evaluator-recovery"
    assert changes["C-05"] == "evaluator-error"
    assert changes["C-06"] == "scope-change"
    assert changes["C-07"] == "control-regression"
    assert changes["C-08"] == "control-improvement"
    assert changes["C-09"] == "unchanged"
    payload = delta.to_dict()
    assert "score" not in payload
    assert "security_score" not in payload
    assert "risk_score" not in payload
    assert delta.before.manifest_sha256 != delta.after.manifest_sha256


def test_governance_delta_round_trip_verification_detects_statement_tampering(
    tmp_path: Path,
) -> None:
    before = _bundle(tmp_path, "abl-before", {"C-01": "PARTIAL", "C-02": "MANUAL"})
    after = _bundle(tmp_path, "abl-after", {"C-01": "PASS", "C-02": "PARTIAL"})
    delta = build_delta(before, after)
    output = write_delta_json(delta, tmp_path / "delta.json")
    html = write_delta_html(delta, tmp_path / "delta.html")

    ok, errors, summary = verify_delta(output, before, after)
    assert ok is True, errors
    assert summary["before_run_id"] == "abl-before"
    assert summary["after_run_id"] == "abl-after"
    assert html.is_file()
    assert "control-improvement" in html.read_text(encoding="utf-8")

    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["changes"][0]["after_status"] = "FAIL"
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    ok, errors, _ = verify_delta(output, before, after)
    assert ok is False
    assert any("does not match recomputed" in error for error in errors)


def test_governance_delta_requires_same_baseline_and_control_set(tmp_path: Path) -> None:
    before = _bundle(tmp_path, "abl-before", {"C-01": "PASS"}, baseline="1.0-draft")
    different_baseline = _bundle(
        tmp_path,
        "abl-after-baseline",
        {"C-01": "PASS"},
        baseline="1.1-draft",
    )
    with pytest.raises(ValueError, match="baseline version mismatch"):
        build_delta(before, different_baseline)

    different_controls = _bundle(
        tmp_path,
        "abl-after-controls",
        {"C-01": "PASS", "C-02": "PASS"},
        baseline="1.0-draft",
    )
    with pytest.raises(ValueError, match="control set mismatch"):
        build_delta(before, different_controls)


def test_governance_delta_warns_on_cross_agent_comparison(tmp_path: Path) -> None:
    before = _bundle(
        tmp_path,
        "abl-before",
        {"C-01": "PASS"},
        agent_id="agent-a",
    )
    after = _bundle(
        tmp_path,
        "abl-after",
        {"C-01": "PASS"},
        agent_id="agent-b",
    )
    delta = build_delta(before, after)
    assert delta.comparison_warnings
    assert "cross-agent" in delta.comparison_warnings[0]
