from __future__ import annotations

import copy
import hashlib
import json
import secrets
import shutil
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .commands import CommandResult, exists, run
from .config import get_path, load_config
from .evidence import EvidenceStore, sha256_file, verify_manifest


@dataclass(frozen=True)
class WorkspaceSnapshot:
    root_sha256: str
    file_count: int
    total_bytes: int
    files: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AgentRunResult:
    session_id: str
    session_dir: str
    sandbox_name: str
    workspace: str
    executed: bool
    returncode: int | None
    config_for_assessment: str


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _snapshot_workspace(root: Path) -> WorkspaceSnapshot:
    entries: dict[str, str] = {}
    total = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        rel = path.relative_to(root).as_posix()
        entries[rel] = sha256_file(path)
        total += path.stat().st_size
    digest = hashlib.sha256()
    for rel, file_hash in entries.items():
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_hash.encode("ascii"))
        digest.update(b"\n")
    return WorkspaceSnapshot(digest.hexdigest(), len(entries), total, entries)


def _changed_paths(before: WorkspaceSnapshot, after: WorkspaceSnapshot) -> dict[str, list[str]]:
    before_keys = set(before.files)
    after_keys = set(after.files)
    return {
        "added": sorted(after_keys - before_keys),
        "removed": sorted(before_keys - after_keys),
        "modified": sorted(
            path
            for path in before_keys & after_keys
            if before.files[path] != after.files[path]
        ),
    }


def _command_meta(result: CommandResult) -> dict[str, Any]:
    stdout = result.stdout.encode("utf-8", errors="replace")
    stderr = result.stderr.encode("utf-8", errors="replace")
    return {
        "returncode": result.returncode,
        "stdout_bytes": len(stdout),
        "stdout_sha256": _sha256_bytes(stdout),
        "stderr_bytes": len(stderr),
        "stderr_sha256": _sha256_bytes(stderr),
    }


def _observe(command: list[str], timeout: int = 20) -> dict[str, Any]:
    result = run(command, timeout=timeout)
    return {"command": command, **_command_meta(result), "stdout": result.stdout, "stderr": result.stderr}


def _redacted_agent_command(command: list[str], prompt_sha256: str) -> list[str]:
    if not command:
        return []
    redacted = list(command)
    if redacted:
        redacted[-1] = f"<prompt sha256:{prompt_sha256}>"
    return redacted


def _make_assessment_config(
    base_cfg: dict[str, Any],
    *,
    session_dir: Path,
    sandbox_name: str,
    workspace: Path,
    agent: str,
    started_at: str,
    completed_at: str,
    enable_audit: bool,
) -> Path:
    cfg = copy.deepcopy(base_cfg)
    cfg.setdefault("sandbox", {})["name"] = sandbox_name
    cfg["sandbox"]["workspace"] = str(workspace)
    assessment = cfg.setdefault("assessment", {})
    assessment["agent_run"] = {"path": str(session_dir / "session.json")}

    # Resolve artifact checks against the disposable workspace. This keeps the
    # base configuration useful for offline runs while ensuring live evidence
    # validates the files the agent actually modified.
    for check in assessment.get("artifact_checks", []) or []:
        if not isinstance(check, dict):
            continue
        command = check.get("command", [])
        if isinstance(command, list):
            check["command"] = [
                str(arg)
                .replace("{workspace}", str(workspace))
                .replace("sample-app", str(workspace))
                for arg in command
            ]

    audit = assessment.setdefault("docker_audit", {})
    if enable_audit:
        audit["enabled"] = True
        audit["agent"] = agent
        audit["since"] = started_at
        audit["until"] = completed_at

    path = session_dir / "assessment-config.yaml"
    path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    return path


def run_agent_task(
    config_path: str | Path,
    task_path: str | Path,
    *,
    output_root: str | Path = ".",
    timeout: int = 900,
    dry_run: bool = False,
    capture_output: bool = False,
    enable_audit: bool = False,
) -> AgentRunResult:
    cfg = load_config(config_path)
    root = Path(output_root).resolve()
    task_file = Path(task_path).resolve()
    if not task_file.is_file():
        raise ValueError(f"Task file not found: {task_file}")

    template = Path(str(get_path(cfg, "sandbox.workspace", "")))
    if not template.is_absolute():
        template = Path.cwd() / template
    template = template.resolve()
    if not template.is_dir():
        raise ValueError(f"Sandbox workspace template not found: {template}")

    task_bytes = task_file.read_bytes()
    task_text = task_bytes.decode("utf-8")
    task_sha256 = _sha256_bytes(task_bytes)
    session_id = (
        "agent-"
        + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + secrets.token_hex(3)
    )
    sandbox_base = str(get_path(cfg, "sandbox.name", "abl-demo")) or "abl-demo"
    sandbox_name = f"{sandbox_base}-{session_id[-6:]}"
    agent = str(get_path(cfg, "sandbox.agent", "codex"))

    session_dir = root / "agent-runs" / session_id
    workspace = root / ".abl-workspaces" / session_id / "workspace"
    session_dir.mkdir(parents=True, exist_ok=False)
    workspace.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(template, workspace)
    store = EvidenceStore(session_dir)

    before = _snapshot_workspace(workspace)
    store.write_json("workspace-before.json", before.to_dict(), "Content-hash inventory before the agent task.")

    deny_hosts = list(get_path(cfg, "sandbox.network.required_denies", []) or [])
    static_mcp = list(get_path(cfg, "sandbox.mcp.static_servers", []) or [])
    command = ["sbx", "run", agent, "--name", sandbox_name]
    for host in deny_hosts:
        command.extend(["--deny-network", str(host)])
    if static_mcp:
        command.extend(["--static-mcp", ",".join(map(str, static_mcp))])
    command.append(str(workspace))
    if agent == "codex":
        command.extend(["--", "--dangerously-bypass-approvals-and-sandbox", task_text])
    else:
        command.extend(["--", task_text])

    started_at = utc_now()
    preflight: dict[str, Any] = {
        "sbx_available": exists("sbx"),
        "agent": agent,
        "sandbox_name": sandbox_name,
        "workspace": str(workspace),
    }
    if exists("sbx"):
        preflight["sbx_version"] = _observe(["sbx", "version"])
        preflight["mcp_registrations"] = _observe(["sbx", "mcp", "ls"])
        secret_result = run(["sbx", "secret", "ls", "--service", "openai"])
        preflight["openai_secret_metadata"] = {
            **_command_meta(secret_result),
            "service_entry_present": bool(secret_result.stdout.strip()),
            "raw_output_persisted": False,
        }
    store.write_json("preflight.json", preflight, "Pre-run Docker Sandboxes readiness metadata.")

    if dry_run:
        execution = CommandResult(command, 0, "", "")
        executed = False
    elif not exists("sbx"):
        execution = CommandResult(command, 127, "", "sbx is not installed")
        executed = False
    else:
        execution = run(command, timeout=timeout)
        executed = True

    completed_at = utc_now()
    output_meta = _command_meta(execution)
    output_meta.update(
        {
            "attempted": executed,
            "dry_run": dry_run,
            "command": _redacted_agent_command(command, task_sha256),
            "prompt_sha256": task_sha256,
            "prompt_bytes": len(task_bytes),
            "raw_prompt_persisted": False,
            "raw_output_persisted": capture_output,
        }
    )
    store.write_json("agent-execution.json", output_meta, "Agent command metadata. Prompt and output are not persisted by default.")
    if capture_output:
        store.write_text("agent-stdout.txt", execution.stdout, "Explicitly requested raw agent stdout.")
        store.write_text("agent-stderr.txt", execution.stderr, "Explicitly requested raw agent stderr.")

    observations: dict[str, Any] = {}
    if exists("sbx") and (executed or not dry_run):
        observations["sandboxes"] = _observe(["sbx", "ls", "--json"])
        observations["policy"] = _observe(["sbx", "policy", "ls", sandbox_name, "--json"])
        observations["policy_log"] = _observe(
            ["sbx", "policy", "log", sandbox_name, "--json", "--limit", "200"]
        )
        observations["mcp"] = _observe(["sbx", "mcp", "ls"])
    store.write_json("docker-observations.json", observations, "Post-task Docker Sandboxes observations.")

    after = _snapshot_workspace(workspace)
    changes = _changed_paths(before, after)
    store.write_json("workspace-after.json", after.to_dict(), "Content-hash inventory after the agent task.")
    store.write_json("workspace-changes.json", changes, "Added, removed and modified workspace paths.")

    session = {
        "schema_version": 1,
        "session_id": session_id,
        "task_id": str(get_path(cfg, "assessment.task_id", "")),
        "agent": agent,
        "sandbox_name": sandbox_name,
        "started_at": started_at,
        "completed_at": completed_at,
        "workspace": str(workspace),
        "workspace_template": str(template),
        "task": {
            "source": str(task_file),
            "sha256": task_sha256,
            "bytes": len(task_bytes),
            "persisted": False,
        },
        "execution": output_meta,
        "workspace_before": {
            "root_sha256": before.root_sha256,
            "file_count": before.file_count,
            "total_bytes": before.total_bytes,
        },
        "workspace_after": {
            "root_sha256": after.root_sha256,
            "file_count": after.file_count,
            "total_bytes": after.total_bytes,
        },
        "changes": changes,
        "evidence_semantics": "metadata-only by default; prompt and agent output are represented by digests",
    }
    store.write_json("session.json", session, "Normalized agent task execution capsule.")

    assessment_config = _make_assessment_config(
        cfg,
        session_dir=session_dir,
        sandbox_name=sandbox_name,
        workspace=workspace,
        agent=agent,
        started_at=started_at,
        completed_at=completed_at,
        enable_audit=enable_audit,
    )
    store.finalize_manifest()

    return AgentRunResult(
        session_id=session_id,
        session_dir=str(session_dir),
        sandbox_name=sandbox_name,
        workspace=str(workspace),
        executed=executed,
        returncode=execution.returncode if executed else None,
        config_for_assessment=str(assessment_config),
    )


def load_agent_run(path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    session_path = Path(path)
    if session_path.is_dir():
        session_path = session_path / "session.json"
    if not session_path.is_file():
        raise ValueError(f"Agent run session not found: {session_path}")
    session = json.loads(session_path.read_text(encoding="utf-8"))
    if session.get("schema_version") != 1:
        raise ValueError("Unsupported agent run session schema")
    ok, errors = verify_manifest(session_path.parent)
    verification = {
        "manifest_valid": ok,
        "manifest_errors": errors,
        "session_path": str(session_path),
    }
    return session, verification


def cleanup_sandbox(name: str) -> CommandResult:
    return run(["sbx", "rm", name], timeout=60)
