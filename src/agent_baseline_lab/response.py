from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .commands import exists, parse_json_output, run


@dataclass
class ResponseDrillResult:
    schema_version: int
    drill_id: str
    sandbox: str
    started_at: str
    completed_at: str
    pre_status: str | None
    post_status: str | None
    stop_returncode: int | None
    stop_stdout: str
    stop_stderr: str
    verified_stopped: bool
    credential_revocation_tested: bool
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _status_from_record(record: dict[str, Any]) -> str | None:
    for key in ("status", "state", "lifecycle", "runtimeStatus"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value.lower()
        if isinstance(value, dict):
            for nested in ("status", "state", "phase"):
                nested_value = value.get(nested)
                if isinstance(nested_value, str) and nested_value:
                    return nested_value.lower()
    return None


def _find_sandbox_status(payload: Any, sandbox: str) -> str | None:
    if isinstance(payload, dict):
        names = [payload.get(key) for key in ("name", "sandbox", "sandboxName", "id")]
        if sandbox in {str(value) for value in names if value is not None}:
            return _status_from_record(payload)
        for value in payload.values():
            observed = _find_sandbox_status(value, sandbox)
            if observed is not None:
                return observed
    elif isinstance(payload, list):
        for value in payload:
            observed = _find_sandbox_status(value, sandbox)
            if observed is not None:
                return observed
    return None


def run_stop_drill(sandbox: str, output_path: str | Path, *, dry_run: bool = False) -> ResponseDrillResult:
    if not sandbox.strip():
        raise ValueError("sandbox name must not be empty")
    if not dry_run and not exists("sbx"):
        raise RuntimeError("Docker Sandboxes CLI (`sbx`) is required for a live response drill")

    started = _utc_now()
    drill_id = "response-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    notes: list[str] = [
        "This drill tests immediate sandbox stop only.",
        "Credential/session revocation remains untested and must not be inferred from sandbox stop.",
    ]

    if dry_run:
        result = ResponseDrillResult(
            schema_version=1,
            drill_id=drill_id,
            sandbox=sandbox,
            started_at=started,
            completed_at=_utc_now(),
            pre_status=None,
            post_status=None,
            stop_returncode=None,
            stop_stdout="",
            stop_stderr="",
            verified_stopped=False,
            credential_revocation_tested=False,
            notes=notes + ["Dry run: no Docker Sandbox command was executed."],
        )
    else:
        before = run(["sbx", "ls", "--json"], timeout=30)
        before_json = parse_json_output(before)
        pre_status = _find_sandbox_status(before_json, sandbox) if before_json is not None else None
        stop = run(["sbx", "stop", sandbox], timeout=60)
        after = run(["sbx", "ls", "--json"], timeout=30)
        after_json = parse_json_output(after)
        post_status = _find_sandbox_status(after_json, sandbox) if after_json is not None else None
        verified = stop.ok and post_status in {"stopped", "stop", "exited", "inactive"}
        if post_status is None:
            notes.append("Post-stop sandbox status could not be parsed from `sbx ls --json`.")
        if stop.ok and not verified:
            notes.append("The stop command succeeded, but a structured stopped state was not independently observed.")
        result = ResponseDrillResult(
            schema_version=1,
            drill_id=drill_id,
            sandbox=sandbox,
            started_at=started,
            completed_at=_utc_now(),
            pre_status=pre_status,
            post_status=post_status,
            stop_returncode=stop.returncode,
            stop_stdout=stop.stdout,
            stop_stderr=stop.stderr,
            verified_stopped=verified,
            credential_revocation_tested=False,
            notes=notes,
        )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def load_response_drill(path: str | Path, *, expected_sandbox: str | None = None) -> tuple[dict[str, Any] | None, list[str]]:
    evidence_path = Path(path)
    if not evidence_path.exists():
        return None, [f"response drill evidence not found: {evidence_path}"]
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"response drill evidence is unreadable: {exc}"]
    errors: list[str] = []
    if payload.get("schema_version") != 1:
        errors.append("unsupported response drill schema_version")
    if expected_sandbox and payload.get("sandbox") != expected_sandbox:
        errors.append(
            f"response drill sandbox mismatch: expected {expected_sandbox}, observed {payload.get('sandbox')}"
        )
    return payload, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explicit Docker Sandbox response drill")
    parser.add_argument("--sandbox", default="abl-demo")
    parser.add_argument("--output", default=".abl/response/abl-demo-stop.json")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run_stop_drill(args.sandbox, args.output, dry_run=args.dry_run)
    except (RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if args.dry_run or result.verified_stopped else 1


if __name__ == "__main__":
    raise SystemExit(main())
