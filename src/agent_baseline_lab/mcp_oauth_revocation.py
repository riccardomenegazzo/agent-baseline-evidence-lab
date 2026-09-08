from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .commands import exists, parse_json_output, run

SAFE_KEYS = {
    "name",
    "server",
    "status",
    "authorized",
    "authenticated",
    "hasCredential",
    "has_credential",
    "expiresAt",
    "expires_at",
    "grantedScopes",
    "granted_scopes",
    "defaultScopes",
    "default_scopes",
    "supportedScopes",
    "supported_scopes",
    "requestedScopes",
    "requested_scopes",
}


@dataclass(frozen=True)
class MCPOAuthRevocationEvidence:
    schema_version: int
    artifact_type: str
    server: str
    started_at: str
    completed_at: str
    dry_run: bool
    confirmed: bool
    before_status_attempted: bool
    before_authorized: bool | None
    before_status: Any
    remove_attempted: bool
    remove_returncode: int | None
    remove_stdout_sha256: str
    remove_stderr_sha256: str
    after_status_attempted: bool
    after_authorized: bool | None
    after_status: Any
    revocation_verified: bool
    scope: str
    secret_material_persisted: bool
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def sanitize_status(value: Any) -> Any:
    if isinstance(value, list):
        return [sanitize_status(item) for item in value]
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if key in SAFE_KEYS:
                cleaned[key] = sanitize_status(item)
            elif isinstance(item, (dict, list)):
                nested = sanitize_status(item)
                if nested not in ({}, []):
                    cleaned[key] = nested
        return cleaned
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def authorization_state(value: Any) -> bool | None:
    if isinstance(value, list):
        states = [authorization_state(item) for item in value]
        recognized = [item for item in states if item is not None]
        if not recognized:
            return None
        if any(recognized):
            return True
        return False
    if isinstance(value, dict):
        for key in ("authorized", "authenticated", "hasCredential", "has_credential"):
            item = value.get(key)
            if isinstance(item, bool):
                return item
        status = value.get("status")
        if isinstance(status, str):
            normalized = status.strip().lower().replace("_", "-")
            if normalized in {"authorized", "authenticated", "valid", "active", "ready"}:
                return True
            if normalized in {
                "unauthorized",
                "not-authorized",
                "not-authenticated",
                "missing",
                "absent",
                "none",
                "revoked",
                "expired",
            }:
                return False
        for item in value.values():
            state = authorization_state(item)
            if state is not None:
                return state
    return None


def _status(server: str) -> tuple[bool, int | None, Any, bool | None]:
    result = run(["sbx", "mcp", "auth", "status", server, "--format=json"], timeout=30)
    parsed = parse_json_output(result)
    if parsed is None:
        fallback = run(["sbx", "mcp", "auth", "status", server, "--json"], timeout=30)
        result = fallback
        parsed = parse_json_output(fallback)
    sanitized = sanitize_status(parsed) if parsed is not None else {}
    return True, result.returncode, sanitized, authorization_state(sanitized)


def revoke_mcp_oauth(
    server: str,
    *,
    output_path: str | Path,
    confirmed: bool = False,
    dry_run: bool = False,
) -> MCPOAuthRevocationEvidence:
    if not server.strip():
        raise ValueError("server name must not be empty")
    if not dry_run and not confirmed:
        raise ValueError("live OAuth revocation requires explicit confirmation")
    if not dry_run and not exists("sbx"):
        raise RuntimeError("Docker Sandboxes CLI (`sbx`) is required for live OAuth revocation")

    started = _utc_now()
    before_attempted = False
    before_status: Any = {}
    before_authorized: bool | None = None
    after_attempted = False
    after_status: Any = {}
    after_authorized: bool | None = None
    remove_attempted = False
    remove_returncode: int | None = None
    remove_stdout = ""
    remove_stderr = ""

    if not dry_run:
        before_attempted, _, before_status, before_authorized = _status(server)
        remove_attempted = True
        removal = run(["sbx", "mcp", "auth", "rm", server], timeout=60)
        remove_returncode = removal.returncode
        remove_stdout = removal.stdout
        remove_stderr = removal.stderr
        after_attempted, _, after_status, after_authorized = _status(server)

    verified = bool(
        not dry_run
        and confirmed
        and before_attempted
        and before_authorized is True
        and remove_attempted
        and remove_returncode == 0
        and after_attempted
        and after_authorized is False
    )
    evidence = MCPOAuthRevocationEvidence(
        schema_version=1,
        artifact_type="mcp-oauth-revocation-evidence",
        server=server,
        started_at=started,
        completed_at=_utc_now(),
        dry_run=dry_run,
        confirmed=confirmed,
        before_status_attempted=before_attempted,
        before_authorized=before_authorized,
        before_status=before_status,
        remove_attempted=remove_attempted,
        remove_returncode=remove_returncode,
        remove_stdout_sha256=_digest(remove_stdout),
        remove_stderr_sha256=_digest(remove_stderr),
        after_status_attempted=after_attempted,
        after_authorized=after_authorized,
        after_status=after_status,
        revocation_verified=verified,
        scope="docker-hosted-mcp-oauth-credential",
        secret_material_persisted=False,
        claims_boundary=(
            "A positive claim requires an observed authorized state before `sbx mcp auth rm`, a "
            "successful removal command, and an independently observed unauthorized/absent state "
            "afterward. This proves removal of Docker-hosted MCP OAuth credentials for this server; "
            "it does not claim revocation of unrelated provider sessions, client secrets, or accounts."
        ),
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explicitly revoke and verify Docker-hosted MCP OAuth credentials")
    parser.add_argument("server")
    parser.add_argument("--output", required=True)
    parser.add_argument("--confirm", action="store_true", help="required for the live mutating operation")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        evidence = revoke_mcp_oauth(
            args.server,
            output_path=args.output,
            confirmed=args.confirm,
            dry_run=args.dry_run,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(evidence.to_dict(), indent=2, sort_keys=True))
    return 0 if args.dry_run or evidence.revocation_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
