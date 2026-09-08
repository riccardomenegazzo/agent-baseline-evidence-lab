from __future__ import annotations

from pathlib import Path

from agent_baseline_lab.mcp_runtime import (
    collect_mcp_runtime_evidence,
    correlate_mcp_action_chains,
    parse_mcp_inspect,
)


def test_parse_mcp_inspect_identity() -> None:
    parsed = parse_mcp_inspect(
        "Name: dhi\nIdentity URL: https://dhi.io/mcp\nTransport: remote\nType: remote-http\n"
    )
    assert parsed["identity_url"] == "https://dhi.io/mcp"
    assert parsed["transport"] == "remote"
    assert parsed["server_type"] == "remote-http"


def test_dry_run_never_claims_runtime_identity(tmp_path: Path) -> None:
    evidence = collect_mcp_runtime_evidence(
        ["dhi"],
        expected_identity_urls={"dhi": "https://dhi.io/mcp"},
        output_path=tmp_path / "mcp.json",
        dry_run=True,
    )
    server = evidence.servers[0]
    assert server.inspect_attempted is False
    assert server.identity_match is None
    assert server.oauth_status_attempted is False
    assert server.oauth_evidence_contains_secret_material is False


def test_correlate_mcp_action_chain_by_session_and_resource() -> None:
    records = [
        {
            "audit_session_id": "session-1",
            "resource_id": "tool:dhi/search",
            "audit_event_id": "e1",
            "timestamp": "2026-09-08T08:00:00Z",
            "category": "AUDIT_CATEGORY_EVALUATION",
            "decision": "MCP_ALLOW",
            "action_type": "tool_invocation",
        },
        {
            "audit_session_id": "session-1",
            "resource_id": "tool:dhi/search",
            "audit_event_id": "e2",
            "timestamp": "2026-09-08T08:00:01Z",
            "category": "AUDIT_CATEGORY_EXECUTION",
            "decision": "",
            "action_type": "tool_execution",
        },
    ]
    chains = correlate_mcp_action_chains(records)
    assert len(chains) == 1
    assert chains[0].evaluation_seen is True
    assert chains[0].execution_seen is True
    assert chains[0].status == "evaluated-executed"


def test_denied_chain_does_not_claim_execution() -> None:
    records = [
        {
            "audit_session_id": "session-1",
            "resource_id": "tool:dangerous",
            "audit_event_id": "e1",
            "timestamp": "2026-09-08T08:00:00Z",
            "category": "AUDIT_CATEGORY_EVALUATION",
            "decision": "MCP_DENY",
            "action_type": "tool_invocation",
        }
    ]
    chains = correlate_mcp_action_chains(records)
    assert chains[0].deny_seen is True
    assert chains[0].execution_seen is False
    assert chains[0].status == "denied-no-execution"
