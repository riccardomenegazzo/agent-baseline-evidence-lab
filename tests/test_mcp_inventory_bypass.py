from __future__ import annotations

from agent_baseline_lab.mcp_bypass import probe_direct_mcp_bypass
from agent_baseline_lab.mcp_inventory import (
    McpRegistration,
    evaluate_inventory,
    parse_mcp_inventory,
    parse_mcp_table,
)


def test_mcp_inventory_identity_matching() -> None:
    payload = {
        "servers": [
            {"name": "dhi", "type": "remote", "url": "https://dhi.io/mcp"},
            {"name": "other", "type": "remote", "url": "https://example.invalid/mcp"},
        ]
    }
    registrations = parse_mcp_inventory(payload)
    assert [registration.name for registration in registrations] == ["dhi", "other"]

    result = evaluate_inventory(
        registrations,
        expected={"dhi": "https://dhi.io/mcp"},
        observed=True,
    )
    assert result.missing_expected_names == []
    assert result.identity_mismatches == []
    assert result.unexpected_names == ["other"]

    mismatch = evaluate_inventory(
        [McpRegistration(name="dhi", url="https://wrong.invalid/mcp", transport="remote", source="test")],
        expected={"dhi": "https://dhi.io/mcp"},
        observed=True,
    )
    assert mismatch.identity_mismatches


def test_documented_mcp_ls_table_is_parsed() -> None:
    table = """NAME                 TYPE     URL/COMMAND
dhi                  remote   https://dhi.io/mcp
local-helper         local    docker run helper
"""
    registrations = parse_mcp_table(table)
    assert [(item.name, item.transport, item.url) for item in registrations] == [
        ("dhi", "remote", "https://dhi.io/mcp"),
        ("local-helper", "local", "docker run helper"),
    ]


def test_mcp_bypass_dry_run_never_claims_blocked() -> None:
    result = probe_direct_mcp_bypass("abl-demo", "dhi.io", dry_run=True)
    assert result.policy_observed is False
    assert result.direct_connection_decision == "unknown"
    assert result.bypass_blocked is False
