from pathlib import Path

from agent_baseline_lab.mcp_policy import analyze_policy


def test_reference_mcp_policy_is_allowlist_oriented():
    policy = Path(__file__).resolve().parents[1] / "policies" / "mcp" / "strict-reference.cedar"
    result = analyze_policy(policy)
    assert result.has_actionless_permit is False
    assert result.has_registration_scope is True
    assert result.has_identity_url_binding is True
    assert result.has_tool_scope is True
    assert result.has_approval_guard is True
    assert result.has_local_stdio_forbid is True
    assert result.has_primordial_scope is True
