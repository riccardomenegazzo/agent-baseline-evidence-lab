from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .commands import exists, run

SUPPORTED_ADAPTERS = {"docker-mcp-oauth"}


@dataclass(frozen=True)
class ProviderRevocationResult:
    schema_version: int
    adapter: str
    target: str
    started_at: str
    completed_at: str
    attempted: bool
    returncode: int | None
    local_credential_removed: bool
    upstream_revocation_proven: bool
    secret_material_persisted: bool
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def revoke(
    adapter: str,
    target: str,
    *,
    dry_run: bool = True,
) -> ProviderRevocationResult:
    if adapter not in SUPPORTED_ADAPTERS:
        raise ValueError(f"unsupported revocation adapter: {adapter}")
    if not target.strip():
        raise ValueError("revocation target is required")
    started = _utc_now()
    if dry_run:
        return ProviderRevocationResult(
            schema_version=1,
            adapter=adapter,
            target=target,
            started_at=started,
            completed_at=_utc_now(),
            attempted=False,
            returncode=None,
            local_credential_removed=False,
            upstream_revocation_proven=False,
            secret_material_persisted=False,
            claims_boundary=(
                "Dry-run only: no credential mutation occurred and no revocation claim is made."
            ),
        )
    if adapter == "docker-mcp-oauth":
        if not exists("sbx"):
            raise RuntimeError("Docker Sandboxes CLI (`sbx`) is required")
        result = run(["sbx", "mcp", "auth", "rm", target], timeout=60)
        return ProviderRevocationResult(
            schema_version=1,
            adapter=adapter,
            target=target,
            started_at=started,
            completed_at=_utc_now(),
            attempted=True,
            returncode=result.returncode,
            local_credential_removed=result.ok,
            upstream_revocation_proven=False,
            secret_material_persisted=False,
            claims_boundary=(
                "For docker-mcp-oauth, success proves removal of the host-managed OAuth access token through sbx. "
                "It does not claim the remote provider invalidated that token server-side unless separate provider evidence establishes that postcondition."
            ),
        )
    raise AssertionError("unreachable adapter")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Execute an explicit credential revocation adapter")
    parser.add_argument("adapter", choices=sorted(SUPPORTED_ADAPTERS))
    parser.add_argument("target")
    parser.add_argument("--execute", action="store_true", help="perform the mutation; default is dry-run")
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)
    try:
        result = revoke(args.adapter, args.target, dry_run=not args.execute)
    except (RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    payload = result.to_dict()
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    if not args.execute:
        return 0
    return 0 if result.local_credential_removed else 1


if __name__ == "__main__":
    raise SystemExit(main())
