from __future__ import annotations

from agent_baseline_lab.mcp_action_chain import analyze_action_chains


def test_complete_observed_tool_chain_is_bounded_not_causal() -> None:
    records = [
        {
            "audit_event_id": "eval-1",
            "timestamp": "2026-09-08T08:00:00Z",
            "audit_session_id": "daemon-1",
            "agent": "codex",
            "resource_id": "dhi/search",
            "category": "AUDIT_CATEGORY_EVALUATION",
            "decision": "AUDIT_DECISION_ALLOW",
            "action_type": "tool_invocation",
        },
        {
            "audit_event_id": "exec-1",
            "timestamp": "2026-09-08T08:00:01Z",
            "audit_session_id": "daemon-1",
            "agent": "codex",
            "resource_id": "dhi/search",
            "category": "AUDIT_CATEGORY_EXECUTION",
            "action_type": "tool_execution",
        },
    ]
    chains = analyze_action_chains(records)
    assert len(chains) == 1
    assert chains[0].status == "complete-observed-chain"
    assert chains[0].confidence == "bounded-multi-event"
    assert chains[0].evaluation_event_ids == ["eval-1"]
    assert chains[0].execution_event_ids == ["exec-1"]


def test_denied_tool_has_no_execution_claim() -> None:
    chains = analyze_action_chains(
        [
            {
                "audit_event_id": "deny-1",
                "timestamp": "2026-09-08T08:00:00Z",
                "audit_session_id": "daemon-1",
                "agent": "codex",
                "resource_id": "dhi/write",
                "category": "AUDIT_CATEGORY_EVALUATION",
                "decision": "AUDIT_DECISION_DENY",
                "action_type": "tool_invocation",
            }
        ]
    )
    assert chains[0].status == "denied-before-execution"
    assert chains[0].execution_event_ids == []


def test_approval_required_without_approved_record_is_not_promoted() -> None:
    chains = analyze_action_chains(
        [
            {
                "audit_event_id": "approval-1",
                "timestamp": "2026-09-08T08:00:00Z",
                "audit_session_id": "daemon-1",
                "agent": "codex",
                "resource_id": "dhi/write",
                "category": "AUDIT_CATEGORY_EVALUATION",
                "decision": "AUDIT_DECISION_APPROVAL_REQUIRED",
                "action_type": "tool_invocation",
            },
            {
                "audit_event_id": "exec-1",
                "timestamp": "2026-09-08T08:00:01Z",
                "audit_session_id": "daemon-1",
                "agent": "codex",
                "resource_id": "dhi/write",
                "category": "AUDIT_CATEGORY_EXECUTION",
                "action_type": "tool_execution",
            },
        ]
    )
    assert chains[0].status == "execution-without-observed-approval"
