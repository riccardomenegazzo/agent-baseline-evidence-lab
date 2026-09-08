from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FallbackEvidence:
    schema_version: int
    artifact_type: str
    run_id: str
    started_at: str
    completed_at: str
    working_directory: str
    command: list[str]
    attempted: bool
    returncode: int | None
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    agent_used: bool
    human_review_required: bool
    verified_success: bool
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_fallback_workflow(
    command: list[str],
    *,
    cwd: str | Path,
    output_path: str | Path,
    timeout: int = 300,
    dry_run: bool = False,
) -> FallbackEvidence:
    if not command or not all(isinstance(item, str) and item for item in command):
        raise ValueError("fallback command must be a non-empty argv list")
    working_dir = Path(cwd).resolve()
    if not working_dir.is_dir():
        raise ValueError(f"fallback working directory not found: {working_dir}")
    started = _utc_now()
    run_id = "fallback-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    if dry_run:
        attempted = False
        returncode: int | None = None
        stdout = b""
        stderr = b""
    else:
        result = subprocess.run(
            command,
            cwd=working_dir,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        attempted = True
        returncode = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    evidence = FallbackEvidence(
        schema_version=1,
        artifact_type="non-agent-fallback-evidence",
        run_id=run_id,
        started_at=started,
        completed_at=_utc_now(),
        working_directory=str(working_dir),
        command=command,
        attempted=attempted,
        returncode=returncode,
        stdout_sha256=_digest(stdout),
        stderr_sha256=_digest(stderr),
        stdout_bytes=len(stdout),
        stderr_bytes=len(stderr),
        agent_used=False,
        human_review_required=True,
        verified_success=attempted and returncode == 0,
        claims_boundary=(
            "This evidence proves only that the declared non-agent command completed successfully. "
            "It does not prove a human actually reviewed every change; human_review_required remains "
            "an explicit process requirement. Raw command output is represented only by digests."
        ),
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Execute and evidence a non-agent fallback workflow")
    parser.add_argument("--command-json", required=True, help="JSON argv list, e.g. '[\"python3\", \"-m\", \"unittest\"]'")
    parser.add_argument("--cwd", default=".")
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        command = json.loads(args.command_json)
        if not isinstance(command, list):
            raise ValueError("--command-json must decode to a list")
        evidence = run_fallback_workflow(
            command,
            cwd=args.cwd,
            output_path=args.output,
            timeout=args.timeout,
            dry_run=args.dry_run,
        )
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    print(json.dumps(evidence.to_dict(), indent=2, sort_keys=True))
    return 0 if args.dry_run or evidence.verified_success else 1


if __name__ == "__main__":
    raise SystemExit(main())
