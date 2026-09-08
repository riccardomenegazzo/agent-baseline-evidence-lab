from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from agent_baseline_lab.evidence import EvidenceStore
from agent_baseline_lab.experiment_protocol import (
    build_experiment_statement,
    verify_statement,
    write_statement_html,
    write_statement_json,
)
from agent_baseline_lab.trace import TraceLedger


def _bundle(
    root: Path,
    run_id: str,
    *,
    task_sha256: str = "a" * 64,
    workspace_sha256: str = "b" * 64,
    treatment_host: str = "exfiltration.invalid",
    include_runtime: bool = True,
) -> Path:
    evidence = root / run_id
    store = EvidenceStore(evidence)
    ledger = TraceLedger(evidence / "trace" / "events.ndjson", run_id)
    ledger.append("assessment.started", actor="lab", action="assess")
    ledger.append("assessment.completed", actor="lab", action="finalize")

    config = {
        "schema_version": 1,
        "baseline": {"version": "1.0-draft"},
        "agent": {
            "id": "customer-agent",
            "access": {"resources": ["workspace"]},
            "capabilities": [{"kind": "external_write", "name": "workspace-write"}],
        },
        "sandbox": {
            "agent": "codex",
            "network": {
                "required_allows": ["api.openai.com"],
                "required_denies": [treatment_host],
            },
            "mcp": {"static_servers": []},
            "capability_profile": {
                "id": "coding-agent-v1",
                "version": "1.0",
                "use_case": "coding-agent",
            },
        },
        "assessment": {
            "task_id": "task-1",
            "mcp_policy_files": ["policies/mcp/strict-reference.cedar"],
        },
    }
    store.write_text(
        "inputs/assessment-config.yaml",
        yaml.safe_dump(config, sort_keys=False),
    )
    store.write_json(
        "observations/agent-run.json",
        {
            "session": {
                "schema_version": 1,
                "session_id": f"agent-{run_id}",
                "task_id": "task-1",
                "agent": "codex",
                "task": {"sha256": task_sha256},
                "workspace_before": {"root_sha256": workspace_sha256},
            },
            "verification": {"manifest_valid": True},
        },
    )
    if include_runtime:
        store.write_text("controls/CON-03/sbx-version.txt", "sbx 0.38.0\n")

    store.write_json(
        "assessment.json",
        {
            "run_id": run_id,
            "baseline_version": "1.0-draft",
            "metadata": {
                "agent_id": "customer-agent",
                "trace_head_sha256": ledger.head_hash,
                "trace_event_count": ledger.sequence,
            },
            "results": [
                {
                    "control_id": "CON-03",
                    "status": "PARTIAL",
                    "summary": "test",
                    "details": [],
                    "evidence": [],
                    "evaluator": "test",
                }
            ],
        },
    )
    store.finalize_manifest()
    return evidence


def test_controlled_experiment_is_eligible_when_invariants_match_and_treatment_changes(
    tmp_path: Path,
) -> None:
    before = _bundle(tmp_path, "abl-before", treatment_host="before.invalid")
    after = _bundle(tmp_path, "abl-after", treatment_host="after.invalid")

    statement = build_experiment_statement(before, after)

    assert statement.eligibility == "ELIGIBLE"
    assert statement.eligible_for_causal_interpretation is True
    assert statement.treatment_changed is True
    assert statement.missing_required_invariants == []
    assert statement.differing_required_invariants == []
    assert all(item.status == "MATCH" for item in statement.invariant_checks)
    assert statement.treatment_checks[0].status == "DIFFERENT"


def test_controlled_experiment_fails_when_task_digest_changes(tmp_path: Path) -> None:
    before = _bundle(tmp_path, "abl-before", task_sha256="a" * 64, treatment_host="before.invalid")
    after = _bundle(tmp_path, "abl-after", task_sha256="c" * 64, treatment_host="after.invalid")

    statement = build_experiment_statement(before, after)

    assert statement.eligibility == "NOT_ELIGIBLE"
    assert statement.eligible_for_causal_interpretation is False
    assert statement.differing_required_invariants == ["task_sha256"]


def test_controlled_experiment_is_fail_closed_when_runtime_evidence_is_missing(
    tmp_path: Path,
) -> None:
    before = _bundle(
        tmp_path,
        "abl-before",
        treatment_host="before.invalid",
        include_runtime=False,
    )
    after = _bundle(tmp_path, "abl-after", treatment_host="after.invalid")

    statement = build_experiment_statement(before, after)

    assert statement.eligibility == "INSUFFICIENT_EVIDENCE"
    assert statement.eligible_for_causal_interpretation is False
    assert statement.missing_required_invariants == ["runtime_fingerprint"]


def test_controlled_experiment_requires_an_observed_treatment_change(tmp_path: Path) -> None:
    before = _bundle(tmp_path, "abl-before")
    after = _bundle(tmp_path, "abl-after")

    statement = build_experiment_statement(before, after)

    assert statement.eligibility == "NOT_ELIGIBLE"
    assert statement.eligible_for_causal_interpretation is False
    assert statement.treatment_changed is False
    assert statement.differing_required_invariants == []


def test_experiment_statement_round_trip_detects_tampering(tmp_path: Path) -> None:
    before = _bundle(tmp_path, "abl-before", treatment_host="before.invalid")
    after = _bundle(tmp_path, "abl-after", treatment_host="after.invalid")
    statement = build_experiment_statement(before, after)
    output = write_statement_json(statement, tmp_path / "experiment.json")
    html = write_statement_html(statement, tmp_path / "experiment.html")

    ok, errors, summary = verify_statement(output, before, after)
    assert ok is True, errors
    assert summary["eligibility"] == "ELIGIBLE"
    assert html.is_file()
    assert "ELIGIBLE" in html.read_text(encoding="utf-8")

    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["eligible_for_causal_interpretation"] = False
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    ok, errors, _ = verify_statement(output, before, after)
    assert ok is False
    assert any("does not match recomputed evidence" in error for error in errors)


def test_controlled_experiment_rejects_same_run_id(tmp_path: Path) -> None:
    before = _bundle(tmp_path / "a", "abl-same", treatment_host="before.invalid")
    after = _bundle(tmp_path / "b", "abl-same", treatment_host="after.invalid")
    with pytest.raises(ValueError, match="distinct before and after run_id"):
        build_experiment_statement(before, after)
