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
    credential_revocation_scope: str | None
    credential_evidence: dict[str, Any]
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


def _secret_listing(sandbox: str) -> tuple[bool, str, Any]:
    listing = run(["sbx", "secret", "ls", "--sandbox", sandbox, "--json"], timeout=30)
    parsed = parse_json_output(listing)
    if listing.ok and parsed is not None:
        return True, listing.stdout, parsed
    fallback = run(["sbx", "secret", "ls", "--sandbox", sandbox], timeout=30)
    return fallback.ok, fallback.stdout or fallback.stderr, None


def _contains_marker(text: str, payload: Any, marker: str) -> bool:
    if marker in text:
        return True
    if payload is not None:
        return marker in json.dumps(payload, sort_keys=True)
    return False


def _exercise_disposable_credential_binding(sandbox: str, drill_id: str) -> tuple[bool, dict[str, Any], list[str]]:
    placeholder = f"abl-drill-{drill_id}"
    host = "credential-drill.invalid"
    env_name = "ABL_DRILL_TOKEN"
    generator = "python3 -c 'import secrets; print(secrets.token_urlsafe(32))'"
    notes: list[str] = []

    set_result = run(
        [
            "sbx",
            "secret",
            "set-custom",
            "--sandbox",
            sandbox,
            "--host",
            host,
            "--env",
            env_name,
            "--placeholder",
            placeholder,
            "--command",
            generator,
        ],
        timeout=60,
    )

    listed_before = False
    before_text = ""
    before_json: Any = None
    remove_result = None
    list_after_ok = False
    after_text = ""
    after_json: Any = None
    try:
        if set_result.ok:
            list_before_ok, before_text, before_json = _secret_listing(sandbox)
            listed_before = list_before_ok and _contains_marker(
                before_text,
                before_json,
                placeholder,
            )
        else:
            notes.append("Disposable custom secret could not be created; revocation was not tested.")
    finally:
        remove_result = run(
            [
                "sbx",
                "secret",
                "rm",
                "--placeholder",
                placeholder,
                "--sandbox",
                sandbox,
                "-f",
            ],
            timeout=30,
        )
        list_after_ok, after_text, after_json = _secret_listing(sandbox)

    still_present = _contains_marker(after_text, after_json, placeholder)
    verified = bool(
        set_result.ok
        and listed_before
        and remove_result.ok
        and list_after_ok
        and not still_present
    )
    if set_result.ok and not listed_before:
        notes.append("Secret creation succeeded, but its placeholder was not independently observed in the scoped listing.")
    if remove_result is not None and remove_result.ok and still_present:
        notes.append("Secret removal returned success, but the placeholder remained visible afterwards.")

    evidence = {
        "scope": "sandbox-custom-secret-binding",
        "sandbox": sandbox,
        "host": host,
        "env": env_name,
        "placeholder": placeholder,
        "secret_material_persisted": False,
        "secret_source": "host command generating random disposable material",
        "set_returncode": set_result.returncode,
        "observed_after_set": listed_before,
        "remove_returncode": remove_result.returncode if remove_result is not None else None,
        "observed_after_remove": still_present,
        "listing_after_remove_ok": list_after_ok,
        "verified_revoked": verified,
    }
    return verified, evidence, notes


def run_stop_drill(
    sandbox: str,
    output_path: str | Path,
    *,
    dry_run: bool = False,
    test_disposable_secret_revocation: bool = False,
) -> ResponseDrillResult:
    if not sandbox.strip():
        raise ValueError("sandbox name must not be empty")
    if not dry_run and not exists("sbx"):
        raise RuntimeError("Docker Sandboxes CLI (`sbx`) is required for a live response drill")

    started = _utc_now()
    drill_id = "response-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    notes: list[str] = [
        "Sandbox stop and credential-binding revocation are assessed as distinct claims.",
        "Credential binding removal does not prove upstream provider token invalidation or session revocation.",
    ]
    credential_revocation_tested = False
    credential_revocation_scope: str | None = None
    credential_evidence: dict[str, Any] = {}

    if dry_run:
        if test_disposable_secret_revocation:
            notes.append("Dry run: disposable secret revocation was requested but not executed.")
        result = ResponseDrillResult(
            schema_version=2,
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
            credential_revocation_scope=None,
            credential_evidence={},
            notes=[*notes, "Dry run: no Docker Sandbox command was executed."],
        )
    else:
        before = run(["sbx", "ls", "--json"], timeout=30)
        before_json = parse_json_output(before)
        pre_status = _find_sandbox_status(before_json, sandbox) if before_json is not None else None

        if test_disposable_secret_revocation:
            (
                credential_revocation_tested,
                credential_evidence,
                credential_notes,
            ) = _exercise_disposable_credential_binding(sandbox, drill_id)
            credential_revocation_scope = "sandbox-custom-secret-binding"
            notes.extend(credential_notes)

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
            schema_version=2,
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
            credential_revocation_tested=credential_revocation_tested,
            credential_revocation_scope=credential_revocation_scope,
            credential_evidence=credential_evidence,
            notes=notes,
        )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def load_response_drill(
    path: str | Path,
    *,
    expected_sandbox: str | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    evidence_path = Path(path)
    if not evidence_path.exists():
        return None, [f"response drill evidence not found: {evidence_path}"]
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"response drill evidence is unreadable: {exc}"]
    errors: list[str] = []
    if payload.get("schema_version") not in {1, 2}:
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
    parser.add_argument(
        "--test-disposable-secret-revocation",
        action="store_true",
        help=(
            "create and remove a uniquely named sandbox-scoped custom secret binding; "
            "never uses real provider credentials"
        ),
    )
    args = parser.parse_args(argv)
    try:
        result = run_stop_drill(
            args.sandbox,
            args.output,
            dry_run=args.dry_run,
            test_disposable_secret_revocation=args.test_disposable_secret_revocation,
        )
    except (RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result.to_dict(), indent=2))
    stop_ok = args.dry_run or result.verified_stopped
    revocation_ok = (
        not args.test_disposable_secret_revocation
        or args.dry_run
        or result.credential_revocation_tested
    )
    return 0 if stop_ok and revocation_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
