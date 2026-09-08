from __future__ import annotations

from pathlib import Path

from agent_baseline_lab.mcp_policy import analyze_policy


def test_dhi_policy_forbids_dynamic_primordial_expansion() -> None:
    analysis = analyze_policy(Path("policies/mcp/dhi-readonly.cedar"))
    assert analysis.has_primordial_scope is True
    assert analysis.has_primordial_forbid is True
    assert analysis.has_primordial_permit is False
    assert analysis.forbidden_primordial_resources == ["code-mode", "mcp-add"]
    assert analysis.has_identity_url_binding is True
    assert analysis.has_local_stdio_forbid is True
