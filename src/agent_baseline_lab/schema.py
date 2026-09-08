from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class SchemaDefinition:
    artifact_type: str
    current_version: int


SCHEMAS = {
    "response-drill": SchemaDefinition("response-drill", 2),
    "ssh-detached-signature": SchemaDefinition("ssh-detached-signature", 1),
    "rekor-transparency-receipt": SchemaDefinition("rekor-transparency-receipt", 1),
    "mcp-runtime-evidence": SchemaDefinition("mcp-runtime-evidence", 1),
    "mcp-action-chain-evidence": SchemaDefinition("mcp-action-chain-evidence", 1),
    "mcp-direct-bypass-evidence": SchemaDefinition("mcp-direct-bypass-evidence", 1),
    "behavior-drift-profile": SchemaDefinition("behavior-drift-profile", 1),
    "behavior-drift-report": SchemaDefinition("behavior-drift-report", 1),
    "unintended-action-report": SchemaDefinition("unintended-action-report", 1),
    "component-quarantine-registry": SchemaDefinition("component-quarantine-registry", 1),
    "non-agent-fallback-evidence": SchemaDefinition("non-agent-fallback-evidence", 1),
    "incident-evidence-bundle": SchemaDefinition("incident-evidence-bundle", 1),
    "completeness-witness": SchemaDefinition("completeness-witness", 1),
}


def infer_artifact_type(payload: dict[str, Any]) -> str | None:
    explicit = payload.get("artifact_type")
    if isinstance(explicit, str) and explicit:
        return explicit
    if "drill_id" in payload and "verified_stopped" in payload:
        return "response-drill"
    if "witness_id" in payload and "expected_event_ids" in payload:
        return "completeness-witness"
    return None


def _migrate_response_1_to_2(payload: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(payload)
    migrated["schema_version"] = 2
    migrated.setdefault("credential_revocation_tested", False)
    migrated.setdefault("credential_revocation_scope", None)
    migrated.setdefault("credential_evidence", {})
    notes = migrated.get("notes")
    if not isinstance(notes, list):
        migrated["notes"] = []
    migrated["artifact_type"] = "response-drill"
    return migrated


MIGRATIONS: dict[tuple[str, int], Callable[[dict[str, Any]], dict[str, Any]]] = {
    ("response-drill", 1): _migrate_response_1_to_2,
}


def inspect_payload(payload: dict[str, Any]) -> dict[str, Any]:
    artifact_type = infer_artifact_type(payload)
    version = payload.get("schema_version")
    definition = SCHEMAS.get(artifact_type or "")
    return {
        "artifact_type": artifact_type,
        "schema_version": version,
        "known_schema": definition is not None,
        "current_version": definition.current_version if definition else None,
        "migration_available": bool(
            artifact_type
            and isinstance(version, int)
            and (artifact_type, version) in MIGRATIONS
        ),
        "is_current": bool(definition and version == definition.current_version),
    }


def migrate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    artifact_type = infer_artifact_type(payload)
    version = payload.get("schema_version")
    if not artifact_type or not isinstance(version, int):
        raise ValueError("artifact type or integer schema_version cannot be inferred")
    definition = SCHEMAS.get(artifact_type)
    if not definition:
        raise ValueError(f"unknown artifact schema: {artifact_type}")
    current = dict(payload)
    while version < definition.current_version:
        migration = MIGRATIONS.get((artifact_type, version))
        if migration is None:
            raise ValueError(f"no migration registered for {artifact_type} v{version}")
        current = migration(current)
        version = int(current.get("schema_version", version))
    if version > definition.current_version:
        raise ValueError(
            f"artifact schema {artifact_type} v{version} is newer than supported v{definition.current_version}"
        )
    return current


def migrate_file(source: str | Path, destination: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("artifact must be a JSON object")
    migrated = migrate_payload(payload)
    output = Path(destination)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(migrated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return migrated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect and migrate Agent Baseline Lab artifact schemas")
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("artifact")
    migrate = sub.add_parser("migrate")
    migrate.add_argument("artifact")
    migrate.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        payload = json.loads(Path(args.artifact).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("artifact must be a JSON object")
        if args.command == "inspect":
            result = inspect_payload(payload)
        else:
            result = migrate_file(args.artifact, args.output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
