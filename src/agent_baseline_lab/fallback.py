from __future__ import annotations

import argparse
import json
import shlex
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .commands import run
from .privacy import portable_path


@dataclass(frozen=True)
class FallbackCheck:
    command: list[str]
    returncode: int
    passed: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FallbackResult:
    schema_version: int
    started_at: str
    completed_at: str
    reviewer: str
    reason: str
    workspace: str
    checks: list[FallbackCheck]
    fallback_verified: bool
    agent_execution_required: bool
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "reviewer": self.reviewer,
            "reason": self.reason,
            "workspace": self.workspace,
            "checks": [check.to_dict() for check in self.checks],
            "fallback_verified": self.fallback_verified,
            "agent_execution_required": self.agent_execution_required,
            "claims_boundary": self.claims_boundary,
        }


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def run_fallback(
    workspace: str | Path,
    *,
    reviewer: str,
    reason: str,
    commands: list[list[str]],
    output_path: str | Path,
    privacy_root: str | Path | None = None,
) -> FallbackResult:
    root = Path(workspace).resolve()
    if not root.is_dir():
        raise ValueError("fallback workspace must exist")
    if not reviewer.strip() or not reason.strip():
        raise ValueError("reviewer and reason are required")
    if not commands:
        raise ValueError("at least one fallback validation command is required")

    evidence_root = Path(privacy_root).resolve() if privacy_root is not None else Path.cwd().resolve()
    started = _utc_now()
    results: list[FallbackCheck] = []
    for command in commands:
        if not command:
            raise ValueError("fallback command must not be empty")
        executed = run(command, timeout=120, cwd=root)
        results.append(
            FallbackCheck(
                command=command,
                returncode=executed.returncode,
                passed=executed.ok,
            )
        )
    result = FallbackResult(
        schema_version=1,
        started_at=started,
        completed_at=_utc_now(),
        reviewer=reviewer,
        reason=reason,
        workspace=portable_path(evidence_root, root),
        checks=results,
        fallback_verified=all(check.passed for check in results),
        agent_execution_required=False,
        claims_boundary=(
            "This proves the declared manual validation path executed without an AI agent. "
            "The persisted workspace is an evidence-safe portable reference, not a host filesystem path. "
            "It does not prove the reviewer personally inspected every code change unless separate review evidence is supplied."
        ),
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Execute a non-agent human fallback validation workflow")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument(
        "--command",
        action="append",
        required=True,
        metavar="COMMAND",
        help="shell-like command string; repeat for multiple checks (executed without shell=True)",
    )
    parser.add_argument("--output", default="reports/fallback.json")
    args = parser.parse_args(argv)
    try:
        commands = [shlex.split(value) for value in args.command]
        result = run_fallback(
            args.workspace,
            reviewer=args.reviewer,
            reason=args.reason,
            commands=commands,
            output_path=args.output,
            privacy_root=Path.cwd(),
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.fallback_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
