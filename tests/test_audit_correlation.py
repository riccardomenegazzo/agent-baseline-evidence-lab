import json
from pathlib import Path

from agent_baseline_lab.audit_correlation import (
    analyze_audit_correlation,
    marker_for_session,
    run_correlation_probe,
)


def _write_records(path: Path, records: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )


def _record(*, event: str, session: str, resource: str, timestamp: str) -> dict:
    return {
        "audit_event_id": event,
        "audit_session_id": session,
        "timestamp": timestamp,
        "schema_version": "1.0",
        "category": "AUDIT_CATEGORY_EVALUATION",
        "decision": "AUDIT_DECISION_DENY",
        "resource_id": resource,
        "action_type": "network_egress",
        "agent": "codex",
    }


def test_marker_for_session_is_deterministic_and_reserved():
    first = marker_for_session("agent-123")
    second = marker_for_session("agent-123")
    assert first == second
    assert first.endswith(".correlation.invalid")
    assert len(first.split(".")[0]) < 64


def test_dry_probe_never_claims_attempt(tmp_path: Path):
    path = tmp_path / "probe.json"
    probe = run_correlation_probe(
        "abl-demo-test",
        "agent-test",
        path,
        dry_run=True,
    )
    assert probe.attempted is False
    assert probe.returncode is None
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["marker_host"] == marker_for_session("agent-test")


def test_exact_marker_requires_resource_match(tmp_path: Path):
    marker = marker_for_session("agent-test")
    audit = tmp_path / "audit.jsonl"
    _write_records(
        audit,
        [
            _record(
                event="event-1",
                session="daemon-1",
                resource=f"{marker}:443",
                timestamp="2026-09-08T00:00:01Z",
            )
        ],
    )
    result = analyze_audit_correlation(
        session_id="agent-test",
        marker_host=marker,
        agent="codex",
        since="2026-09-08T00:00:00Z",
        until="2026-09-08T00:01:00Z",
        source=audit,
    )
    assert result.strength == "exact-marker"
    assert result.exact_marker_match is True
    assert result.matched_event_ids == ["event-1"]
    assert result.matched_audit_session_ids == ["daemon-1"]


def test_single_session_is_not_promoted_to_exact(tmp_path: Path):
    marker = marker_for_session("agent-test")
    audit = tmp_path / "audit.jsonl"
    _write_records(
        audit,
        [
            _record(
                event="event-1",
                session="daemon-1",
                resource="github.com:443",
                timestamp="2026-09-08T00:00:01Z",
            )
        ],
    )
    result = analyze_audit_correlation(
        session_id="agent-test",
        marker_host=marker,
        agent="codex",
        since="2026-09-08T00:00:00Z",
        until="2026-09-08T00:01:00Z",
        source=audit,
    )
    assert result.strength == "single-daemon-session"
    assert result.exact_marker_match is False


def test_multiple_daemon_sessions_are_ambiguous(tmp_path: Path):
    marker = marker_for_session("agent-test")
    audit = tmp_path / "audit.jsonl"
    _write_records(
        audit,
        [
            _record(
                event="event-1",
                session="daemon-1",
                resource="github.com:443",
                timestamp="2026-09-08T00:00:01Z",
            ),
            _record(
                event="event-2",
                session="daemon-2",
                resource="dhi.io:443",
                timestamp="2026-09-08T00:00:02Z",
            ),
        ],
    )
    result = analyze_audit_correlation(
        session_id="agent-test",
        marker_host=marker,
        agent="codex",
        since="2026-09-08T00:00:00Z",
        until="2026-09-08T00:01:00Z",
        source=audit,
    )
    assert result.strength == "ambiguous-multi-session"
    assert result.exact_marker_match is False
