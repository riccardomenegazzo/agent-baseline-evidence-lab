from __future__ import annotations

from pathlib import Path

from agent_baseline_lab.mcp_bypass import evaluate_direct_mcp_bypass


def test_dry_run_never_claims_direct_path_blocked(tmp_path: Path) -> None:
    policy = tmp_path / "policy.cedar"
    policy.write_text(
        'permit (principal, action == MCP::Action::"register", resource)\n'
        'when { resource.identityURL == "https://dhi.io/mcp" };\n'
        'permit (principal, action == MCP::Action::"invokeTool", resource)\n'
        'when { resource in MCP::Server::"dhi" };\n',
        encoding="utf-8",
    )
    result = evaluate_direct_mcp_bypass(
        sandbox="abl-demo",
        server_url="https://dhi.io/mcp",
        policy_file=policy,
        output_path=tmp_path / "bypass.json",
        dry_run=True,
    )
    assert result.gateway_policy_scopes_registration is True
    assert result.gateway_policy_scopes_tools is True
    assert result.network_check_attempted is False
    assert result.direct_connection_blocked_by_network_policy is None
    assert result.defense_in_depth_verified is False
