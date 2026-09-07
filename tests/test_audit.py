import json
from pathlib import Path

from agent_baseline_lab.audit import load_audit_records, normalized_event_types


def test_audit_ingest_redacts_identity_and_filters_session(tmp_path: Path):
    audit = tmp_path / "audit-20260907-demo-1.jsonl"
    audit.write_text(
        '{"audit_event_id":"1","timestamp":"2026-09-07T20:00:00Z","schema_version":"1.82.0","category":"AUDIT_CATEGORY_EVALUATION","decision":"AUDIT_DECISION_DENY","username":"alice","user_email":"alice@example.com","org_id":"org-1","org_name":"Acme","audit_session_id":"session-a","resource_id":"example.com:443","hostname":"macbook","action_type":"network_egress","agent":"codex"}\n'
        '{"audit_event_id":"2","timestamp":"2026-09-07T20:00:01Z","schema_version":"1.82.0","category":"AUDIT_CATEGORY_EVALUATION","decision":"AUDIT_DECISION_ALLOW","username":"bob","audit_session_id":"session-b","resource_id":"github.com:443","action_type":"network_egress","agent":"claude"}\n',
        encoding="utf-8",
    )
    # In-progress files are intentionally ignored as evidence, but surfaced in the summary.
    (tmp_path / "audit-in-progress.tmp").write_text('{"audit_event_id":"x"}\n', encoding="utf-8")

    records, summary = load_audit_records(
        tmp_path,
        audit_session_id="session-a",
        agent="codex",
        redaction_salt="run-1",
    )

    assert len(records) == 1
    assert records[0]["username"].startswith("sha256:")
    assert records[0]["user_email"].startswith("sha256:")
    assert records[0]["hostname"].startswith("sha256:")
    assert records[0]["username"] != "alice"
    assert summary.records_seen == 2
    assert summary.records_selected == 1
    assert summary.in_progress_files == 1
    assert summary.audit_session_ids == ["session-a"]
    assert summary.decisions == {"AUDIT_DECISION_DENY": 1}
    assert summary.action_types == {"network_egress": 1}


def test_audit_time_window_filters_records(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps({"timestamp": "2026-09-08T00:00:00Z", "agent": "codex", "audit_event_id": "a"}),
                json.dumps({"timestamp": "2026-09-08T00:05:00Z", "agent": "codex", "audit_event_id": "b"}),
                json.dumps({"timestamp": "2026-09-08T00:10:00Z", "agent": "codex", "audit_event_id": "c"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    records, summary = load_audit_records(
        path,
        agent="codex",
        since="2026-09-08T00:04:00+00:00",
        until="2026-09-08T00:06:00+00:00",
    )
    assert [record["audit_event_id"] for record in records] == ["b"]
    assert summary.records_selected == 1
    assert summary.in_progress_files == 0


def test_tool_invocation_evaluation_maps_to_mcp_policy_and_source_events() -> None:
    record = {
        "category": "AUDIT_CATEGORY_EVALUATION",
        "action_type": "tool_invocation",
        "decision": "AUDIT_DECISION_ALLOW",
    }
    assert normalized_event_types(record) == ["mcp.tool", "policy.decision", "docker.audit"]


def test_tool_execution_maps_to_mcp_tool_and_source_event() -> None:
    record = {
        "category": "AUDIT_CATEGORY_EXECUTION",
        "action_type": "tool_execution",
    }
    assert normalized_event_types(record) == ["mcp.tool", "docker.audit"]


def test_server_registration_is_semantically_distinct() -> None:
    record = {
        "category": "AUDIT_CATEGORY_EVALUATION",
        "action_type": "server_registration",
    }
    assert normalized_event_types(record) == [
        "mcp.registration",
        "policy.decision",
        "docker.audit",
    ]
