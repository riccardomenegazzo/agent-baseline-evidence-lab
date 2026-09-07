from pathlib import Path

from agent_baseline_lab.audit import load_audit_records


def test_audit_ingest_redacts_identity_and_filters_session(tmp_path: Path):
    audit = tmp_path / "audit-20260907-demo-1.jsonl"
    audit.write_text(
        '{"audit_event_id":"1","timestamp":"2026-09-07T20:00:00Z","schema_version":"1.82.0","category":"AUDIT_CATEGORY_EVALUATION","decision":"AUDIT_DECISION_DENY","username":"alice","user_email":"alice@example.com","org_id":"org-1","org_name":"Acme","audit_session_id":"session-a","resource_id":"example.com:443","hostname":"macbook","action_type":"network_egress","agent":"codex"}\n'
        '{"audit_event_id":"2","timestamp":"2026-09-07T20:00:01Z","schema_version":"1.82.0","category":"AUDIT_CATEGORY_EVALUATION","decision":"AUDIT_DECISION_ALLOW","username":"bob","audit_session_id":"session-b","resource_id":"github.com:443","action_type":"network_egress","agent":"claude"}\n',
        encoding="utf-8",
    )
    (tmp_path / "audit-in-progress.tmp").write_text('{"audit_event_id":"x"}\n', encoding="utf-8")
    records, summary = load_audit_records(tmp_path, audit_session_id="session-a", agent="codex", redaction_salt="run-1")
    assert len(records) == 1
    assert records[0]["username"].startswith("sha256:")
    assert records[0]["user_email"].startswith("sha256:")
    assert records[0]["hostname"].startswith("sha256:")
    assert records[0]["username"] != "alice"
    assert summary.records_seen == 2
    assert summary.records_selected == 1
    assert summary.audit_session_ids == ["session-a"]
    assert summary.decisions == {"AUDIT_DECISION_DENY": 1}
    assert summary.action_types == {"network_egress": 1}
