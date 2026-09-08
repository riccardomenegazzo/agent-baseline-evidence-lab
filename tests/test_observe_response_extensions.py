from __future__ import annotations

import json
from pathlib import Path

from agent_baseline_lab.drift import BehavioralBaseline, compare_baseline
from agent_baseline_lab.fallback import run_fallback
from agent_baseline_lab.provider_revocation import revoke
from agent_baseline_lab.unintended_action import analyze_changed_paths


def test_behavioral_drift_detects_new_destination_and_tool() -> None:
    baseline = BehavioralBaseline(
        schema_version=1,
        event_type_counts={"network.egress": 1, "mcp.tool": 1},
        network_destinations=["api.openai.com"],
        mcp_targets=["dhi/search"],
        source_trace_sha256="a" * 64,
    )
    current = BehavioralBaseline(
        schema_version=1,
        event_type_counts={"network.egress": 2, "mcp.tool": 2},
        network_destinations=["api.openai.com", "unexpected.example"],
        mcp_targets=["dhi/search", "unknown/write"],
        source_trace_sha256="b" * 64,
    )
    result = compare_baseline(baseline, current)
    assert result.drift_detected is True
    assert result.new_network_destinations == ["unexpected.example"]
    assert result.new_mcp_targets == ["unknown/write"]


def test_unintended_action_detector_uses_paths_only() -> None:
    result = analyze_changed_paths(
        {
            "added": ["src/app.py", ".env"],
            "modified": [],
            "removed": [],
        }
    )
    assert result.co_change_detected is True
    assert result.sensitive_paths == [".env"]
    assert result.code_paths == ["src/app.py"]


def test_human_fallback_executes_without_agent(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "ok.txt").write_text("ok\n", encoding="utf-8")
    output = tmp_path / "fallback.json"
    result = run_fallback(
        workspace,
        reviewer="human-reviewer",
        reason="agent disabled for response exercise",
        commands=[["python3", "-c", "from pathlib import Path; assert Path('ok.txt').exists()"]],
        output_path=output,
        privacy_root=tmp_path,
    )
    assert result.fallback_verified is True
    assert result.agent_execution_required is False
    assert result.workspace == "workspace"
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["reviewer"] == "human-reviewer"
    assert payload["workspace"] == "workspace"
    assert str(tmp_path) not in output.read_text(encoding="utf-8")


def test_provider_revocation_is_fail_closed_by_default() -> None:
    result = revoke("docker-mcp-oauth", "dhi", dry_run=True)
    assert result.attempted is False
    assert result.local_credential_removed is False
    assert result.upstream_revocation_proven is False
    assert result.secret_material_persisted is False
