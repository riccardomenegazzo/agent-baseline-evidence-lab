import json
from pathlib import Path

import yaml

from agent_baseline_lab.catalog import CONTROLS
from agent_baseline_lab.engine import run_assessment
from agent_baseline_lab.models import Status


def test_engine_emits_all_35_controls(tmp_path: Path):
    config = Path(__file__).resolve().parents[1] / "examples" / "agent.yaml"
    report, json_path, html_path = run_assessment(config, tmp_path)
    assert len(CONTROLS) == 35
    assert len(report.results) == 35
    assert json_path.exists()
    assert html_path.exists()
    evidence = tmp_path / "evidence" / report.run_id
    assert (evidence / "manifest.sha256.json").exists()


def test_engine_correlates_docker_mcp_audit_into_semantic_trace(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    source_cfg = yaml.safe_load((repo / "examples" / "agent.yaml").read_text(encoding="utf-8"))

    audit_file = tmp_path / "docker-audit.jsonl"
    audit_file.write_text(
        json.dumps(
            {
                "audit_event_id": "mcp-eval-1",
                "timestamp": "2026-09-08T00:00:00Z",
                "schema_version": "1.82.0",
                "category": "AUDIT_CATEGORY_EVALUATION",
                "decision": "AUDIT_DECISION_ALLOW",
                "audit_session_id": "docker-session-1",
                "resource_id": "dhi:read-image",
                "action_type": "tool_invocation",
                "agent": "codex",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    source_cfg["assessment"]["docker_audit"] = {
        "enabled": True,
        "path": str(audit_file),
        "audit_session_id": "docker-session-1",
        "agent": "codex",
        "max_records": 100,
    }
    config = tmp_path / "agent-with-audit.yaml"
    config.write_text(yaml.safe_dump(source_cfg, sort_keys=False), encoding="utf-8")

    report, _, _ = run_assessment(config, tmp_path)
    evidence = tmp_path / "evidence" / report.run_id
    events = [
        json.loads(line)
        for line in (evidence / "trace" / "events.ndjson").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    derived = [
        event
        for event in events
        if event.get("attributes", {}).get("audit_event_id") == "mcp-eval-1"
    ]

    assert {event["event_type"] for event in derived} == {
        "mcp.tool",
        "policy.decision",
        "docker.audit",
    }
    assert {event["attributes"]["audit_event_id"] for event in derived} == {"mcp-eval-1"}

    aut01 = next(result for result in report.results if result.control_id == "AUT-01")
    assert aut01.status == Status.PARTIAL

    telemetry = json.loads(
        (evidence / "controls" / "OBS-01" / "telemetry-coverage.json").read_text(
            encoding="utf-8"
        )
    )
    assert telemetry["dimensions"]["mcp_tool_invocation"] is True
    assert telemetry["dimensions"]["policy_decision"] is True
