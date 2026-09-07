from agent_baseline_lab.correlation import correlate_tool_events


def _event(
    event_id: str,
    timestamp: str,
    *,
    category: str,
    action_type: str,
    decision: str = "",
    session: str = "session-1",
    resource: str = "dhi/search",
    agent: str = "codex",
):
    return {
        "audit_event_id": event_id,
        "timestamp": timestamp,
        "schema_version": "1.82.0",
        "category": category,
        "decision": decision,
        "audit_session_id": session,
        "resource_id": resource,
        "action_type": action_type,
        "agent": agent,
    }


def test_pairs_allowed_invocation_with_nearest_execution() -> None:
    records = [
        _event(
            "eval-1",
            "2026-09-08T00:00:00Z",
            category="AUDIT_CATEGORY_EVALUATION",
            action_type="tool_invocation",
            decision="AUDIT_DECISION_ALLOW",
        ),
        _event(
            "exec-1",
            "2026-09-08T00:00:00.250000Z",
            category="AUDIT_CATEGORY_EXECUTION",
            action_type="tool_execution",
        ),
    ]

    report = correlate_tool_events(records)

    assert report.paired_allowed == 1
    assert report.coverage == 1.0
    assert report.complete is True
    assert report.pairs[0].evaluation_event_id == "eval-1"
    assert report.pairs[0].execution_event_id == "exec-1"
    assert report.pairs[0].latency_ms == 250
    assert report.pairs[0].confidence == "heuristic"


def test_denied_invocation_does_not_require_execution() -> None:
    records = [
        _event(
            "eval-deny",
            "2026-09-08T00:00:00Z",
            category="AUDIT_CATEGORY_EVALUATION",
            action_type="tool_invocation",
            decision="AUDIT_DECISION_DENY",
        )
    ]

    report = correlate_tool_events(records)

    assert report.terminal_blocked == 1
    assert report.terminal_allowed == 0
    assert report.unmatched_allowed == []
    assert report.orphan_executions == []
    assert report.coverage is None
    assert report.complete is False


def test_reports_unmatched_allowed_and_orphan_execution() -> None:
    records = [
        _event(
            "eval-1",
            "2026-09-08T00:00:00Z",
            category="AUDIT_CATEGORY_EVALUATION",
            action_type="tool_invocation",
            decision="AUDIT_DECISION_ALLOW",
            resource="dhi/search",
        ),
        _event(
            "exec-other",
            "2026-09-08T00:00:01Z",
            category="AUDIT_CATEGORY_EXECUTION",
            action_type="tool_execution",
            resource="dhi/get-cves",
        ),
    ]

    report = correlate_tool_events(records)

    assert report.paired_allowed == 0
    assert len(report.unmatched_allowed) == 1
    assert len(report.orphan_executions) == 1
    assert report.coverage == 0.0
    assert report.complete is False


def test_does_not_pair_execution_outside_time_window() -> None:
    records = [
        _event(
            "eval-1",
            "2026-09-08T00:00:00Z",
            category="AUDIT_CATEGORY_EVALUATION",
            action_type="tool_invocation",
            decision="AUDIT_DECISION_ALLOW",
        ),
        _event(
            "exec-1",
            "2026-09-08T00:01:00Z",
            category="AUDIT_CATEGORY_EXECUTION",
            action_type="tool_execution",
        ),
    ]

    report = correlate_tool_events(records, max_gap_seconds=5)

    assert report.paired_allowed == 0
    assert len(report.unmatched_allowed) == 1
    assert len(report.orphan_executions) == 1


def test_requires_same_daemon_session() -> None:
    records = [
        _event(
            "eval-1",
            "2026-09-08T00:00:00Z",
            category="AUDIT_CATEGORY_EVALUATION",
            action_type="tool_invocation",
            decision="AUDIT_DECISION_ALLOW",
            session="session-a",
        ),
        _event(
            "exec-1",
            "2026-09-08T00:00:00.100000Z",
            category="AUDIT_CATEGORY_EXECUTION",
            action_type="tool_execution",
            session="session-b",
        ),
    ]

    report = correlate_tool_events(records)

    assert report.paired_allowed == 0
    assert len(report.unmatched_allowed) == 1
    assert len(report.orphan_executions) == 1
