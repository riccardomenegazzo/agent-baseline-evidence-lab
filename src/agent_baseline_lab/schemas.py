from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

CURRENT_SCHEMAS = {
    "response-drill": 2,
    "interview-demo": 3,
}


class SchemaMigrationError(ValueError):
    pass


def _migrate_response(payload: dict[str, Any]) -> dict[str, Any]:
    version = int(payload.get("schema_version", 1))
    if version > CURRENT_SCHEMAS["response-drill"]:
        raise SchemaMigrationError(f"response-drill schema {version} is newer than supported")
    migrated = copy.deepcopy(payload)
    if version == 1:
        migrated.setdefault("credential_revocation_tested", False)
        migrated.setdefault("credential_revocation_scope", None)
        migrated.setdefault("credential_evidence", {})
        migrated["schema_version"] = 2
        version = 2
    if version != 2:
        raise SchemaMigrationError(f"unsupported response-drill schema {version}")
    return migrated


def _migrate_interview(payload: dict[str, Any]) -> dict[str, Any]:
    version = int(payload.get("schema_version", 1))
    if version > CURRENT_SCHEMAS["interview-demo"]:
        raise SchemaMigrationError(f"interview-demo schema {version} is newer than supported")
    migrated = copy.deepcopy(payload)
    if version == 1:
        migrated.setdefault("audit_correlation_requested", False)
        migrated.setdefault("audit_correlation_probe_attempted", False)
        migrated.setdefault("audit_correlation_strength", "legacy-not-observed")
        migrated.setdefault("audit_correlation_exact_marker", False)
        migrated.setdefault("audit_correlation_report", "")
        migrated["schema_version"] = 2
        version = 2
    if version == 2:
        migrated.setdefault("quarantine_registered", False)
        migrated.setdefault("quarantine_registry", "")
        migrated.setdefault("incident_bundle", "")
        migrated.setdefault("incident_bundle_verified", False)
        migrated["schema_version"] = 3
        version = 3
    if version != 3:
        raise SchemaMigrationError(f"unsupported interview-demo schema {version}")
    return migrated


def migrate_payload(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SchemaMigrationError("artifact payload must be a JSON object")
    if kind == "response-drill":
        return _migrate_response(payload)
    if kind == "interview-demo":
        return _migrate_interview(payload)
    raise SchemaMigrationError(f"unsupported artifact kind: {kind}")


def migrate_file(kind: str, source: str | Path, output: str | Path) -> dict[str, Any]:
    source_path = Path(source)
    payload = json.loads(source_path.read_text(encoding="utf-8"))
    migrated = migrate_payload(kind, payload)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(migrated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return migrated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Migrate Agent Baseline evidence artifacts without inventing positive claims")
    parser.add_argument("kind", choices=sorted(CURRENT_SCHEMAS))
    parser.add_argument("source")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        migrated = migrate_file(args.kind, args.source, args.output)
    except (OSError, json.JSONDecodeError, SchemaMigrationError) as exc:
        parser.error(str(exc))
    print(json.dumps(migrated, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
