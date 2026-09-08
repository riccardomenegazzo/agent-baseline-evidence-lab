from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .commands import exists, parse_json_output, run

SENSITIVE_FRAGMENTS = {"token", "secret", "password", "cookie", "authorization", "credential"}


@dataclass(frozen=True)
class OAuthStateResult:
    schema_version: int
    server: str
    observed: bool
    command_returncode: int | None
    raw_output_sha256: str
    sanitized_status: Any
    sensitive_fields_removed: list[str]
    raw_output_persisted: bool
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _is_sensitive(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(fragment in lowered for fragment in SENSITIVE_FRAGMENTS)


def sanitize(value: Any, *, path: str = "") -> tuple[Any, list[str]]:
    removed: list[str] = []
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}" if path else key_text
            if _is_sensitive(key_text):
                removed.append(child_path)
                continue
            cleaned, nested_removed = sanitize(child, path=child_path)
            sanitized[key_text] = cleaned
            removed.extend(nested_removed)
        return sanitized, removed
    if isinstance(value, list):
        sanitized_items: list[Any] = []
        for index, child in enumerate(value):
            cleaned, nested_removed = sanitize(child, path=f"{path}[{index}]")
            sanitized_items.append(cleaned)
            removed.extend(nested_removed)
        return sanitized_items, removed
    return value, removed


def observe_oauth_state(server: str, *, dry_run: bool = False) -> OAuthStateResult:
    if not server.strip():
        raise ValueError("server is required")
    if dry_run or not exists("sbx"):
        return OAuthStateResult(
            schema_version=1,
            server=server,
            observed=False,
            command_returncode=None,
            raw_output_sha256=_digest(""),
            sanitized_status={},
            sensitive_fields_removed=[],
            raw_output_persisted=False,
            claims_boundary=(
                "No live OAuth status was observed. Dry-run or missing sbx cannot establish authorization state."
            ),
        )

    result = run(["sbx", "mcp", "auth", "status", server, "--format=json"], timeout=30)
    parsed = parse_json_output(result)
    sanitized, removed = sanitize(parsed if parsed is not None else {})
    return OAuthStateResult(
        schema_version=1,
        server=server,
        observed=result.ok and parsed is not None,
        command_returncode=result.returncode,
        raw_output_sha256=_digest(result.stdout),
        sanitized_status=sanitized,
        sensitive_fields_removed=sorted(set(removed)),
        raw_output_persisted=False,
        claims_boundary=(
            "This records Docker-reported OAuth authorization metadata without persisting raw command output or secret-like fields. "
            "It does not expose token values, prove remote token validity beyond the reported state, or trigger authorization/refresh."
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Observe MCP OAuth state without collecting secret material")
    parser.add_argument("server")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)
    try:
        result = observe_oauth_state(args.server, dry_run=args.dry_run)
    except ValueError as exc:
        parser.error(str(exc))
    payload = result.to_dict()
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    if args.dry_run:
        return 0
    return 0 if result.observed else 1


if __name__ == "__main__":
    raise SystemExit(main())
