from __future__ import annotations

import json
from pathlib import Path

import agent_baseline_lab.live_run as live_run
from agent_baseline_lab.commands import CommandResult
from agent_baseline_lab.live_run import load_agent_run, run_agent_task


def test_dry_run_creates_metadata_only_capsule(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    result = run_agent_task(
        "examples/agent.yaml",
        "examples/task.md",
        output_root=tmp_path,
        dry_run=True,
    )
    session_path = Path(result.session_dir) / "session.json"
    session = json.loads(session_path.read_text(encoding="utf-8"))
    execution = session["execution"]
    assert execution["dry_run"] is True
    assert execution["attempted"] is False
    assert execution["raw_prompt_persisted"] is False
    assert "Add a `/health` endpoint" not in json.dumps(session)
    assert execution["command"][-1].startswith("<prompt sha256:")

    loaded, verification = load_agent_run(session_path)
    assert loaded["session_id"] == result.session_id
    assert verification["manifest_valid"] is True


def test_dry_run_uses_disposable_workspace(tmp_path: Path, monkeypatch) -> None:
    repo = Path(__file__).resolve().parents[1]
    monkeypatch.chdir(repo)
    result = run_agent_task(
        "examples/agent.yaml",
        "examples/task.md",
        output_root=tmp_path,
        dry_run=True,
    )
    workspace = Path(result.workspace)
    assert workspace != (repo / "sample-app").resolve()
    assert (workspace / "app.py").exists()


def test_live_run_builds_static_mcp_command_without_persisting_prompt(tmp_path: Path, monkeypatch) -> None:
    repo = Path(__file__).resolve().parents[1]
    monkeypatch.chdir(repo)
    monkeypatch.setattr(live_run, "exists", lambda binary: binary == "sbx")
    monkeypatch.setattr(
        live_run,
        "run",
        lambda args, timeout=20: CommandResult(list(args), 0, "dhi remote https://dhi.io/mcp", ""),
    )
    result = live_run.run_agent_task(
        "examples/agent-mcp.yaml",
        "examples/task-mcp.md",
        output_root=tmp_path,
    )
    execution = json.loads(
        (Path(result.session_dir) / "agent-execution.json").read_text(encoding="utf-8")
    )
    command = execution["command"]
    assert "--static-mcp" in command
    assert "dhi" in command
    assert command[-1].startswith("<prompt sha256:")
    assert "Docker Hardened Images" not in json.dumps(execution)
