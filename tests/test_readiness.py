from __future__ import annotations

from pathlib import Path

from agent_baseline_lab import readiness
from agent_baseline_lab.commands import CommandResult
from agent_baseline_lab.mcp_inventory import McpRegistration


def _prepare_root(tmp_path: Path) -> Path:
    examples = tmp_path / "examples"
    examples.mkdir()
    (examples / "agent.yaml").write_text("schema_version: 1\n", encoding="utf-8")
    (examples / "agent-mcp.yaml").write_text("schema_version: 1\n", encoding="utf-8")
    return tmp_path


def test_community_readiness_passes_with_required_prerequisites(tmp_path: Path, monkeypatch) -> None:
    root = _prepare_root(tmp_path)
    monkeypatch.setattr(readiness, "exists", lambda binary: True)
    monkeypatch.setattr(
        readiness,
        "run",
        lambda args, timeout=15: CommandResult(list(args), 0, "version-ok", ""),
    )
    monkeypatch.setattr(
        readiness,
        "verify_lock",
        lambda cache: (True, [], {"valid": True, "source_sha256": "abc"}),
    )

    summary = readiness.run_readiness(root, profile="community")

    assert summary.ready is True
    assert summary.required_failures == 0
    assert any(check.name == "signing-keypair" and check.status == "WARN" for check in summary.checks)


def test_mcp_readiness_fails_when_expected_registration_is_missing(tmp_path: Path, monkeypatch) -> None:
    root = _prepare_root(tmp_path)
    monkeypatch.setattr(readiness, "exists", lambda binary: True)
    monkeypatch.setattr(
        readiness,
        "run",
        lambda args, timeout=15: CommandResult(list(args), 0, "version-ok", ""),
    )
    monkeypatch.setattr(readiness, "verify_lock", lambda cache: (True, [], {"valid": True}))
    monkeypatch.setattr(
        readiness,
        "collect_mcp_inventory",
        lambda: (
            True,
            [
                McpRegistration(
                    name="other",
                    url="https://example.invalid/mcp",
                    transport="remote",
                    source="test",
                )
            ],
            "",
        ),
    )

    summary = readiness.run_readiness(root, profile="mcp")

    assert summary.ready is False
    assert summary.required_failures == 1
    mcp = next(check for check in summary.checks if check.name == "mcp-registration:dhi")
    assert mcp.status == "FAIL"
