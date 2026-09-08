from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .evidence import sha256_file


@dataclass(frozen=True)
class QuarantineEntry:
    schema_version: int
    quarantine_id: str
    created_at: str
    component_type: str
    component_id: str
    reason: str
    source_run_id: str
    response_evidence_sha256: str
    state: str
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def create_quarantine_entry(
    registry_path: str | Path,
    *,
    component_type: str,
    component_id: str,
    reason: str,
    source_run_id: str,
    response_evidence_path: str | Path,
) -> QuarantineEntry:
    if not component_type.strip() or not component_id.strip() or not reason.strip():
        raise ValueError("component_type, component_id, and reason are required")
    response_path = Path(response_evidence_path)
    if not response_path.exists():
        raise ValueError("response evidence must exist before quarantine registration")

    created = _utc_now()
    compact = created.replace(":", "").replace("+00:00", "Z")
    entry = QuarantineEntry(
        schema_version=1,
        quarantine_id=f"quarantine-{compact}-{component_type}-{component_id}",
        created_at=created,
        component_type=component_type,
        component_id=component_id,
        reason=reason,
        source_run_id=source_run_id,
        response_evidence_sha256=sha256_file(response_path),
        state="quarantined",
        claims_boundary=(
            "This registry records an observed or operator-declared quarantine decision. "
            "It does not claim the component is technically isolated unless separate response evidence proves that postcondition."
        ),
    )
    registry = Path(registry_path)
    registry.parent.mkdir(parents=True, exist_ok=True)
    with registry.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
    return entry


def load_registry(path: str | Path) -> list[dict[str, Any]]:
    registry = Path(path)
    if not registry.exists():
        return []
    entries: list[dict[str, Any]] = []
    for line_no, line in enumerate(registry.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError(f"registry line {line_no} is not an object")
        entries.append(payload)
    return entries


def verify_registry(path: str | Path) -> tuple[bool, list[str], dict[str, Any]]:
    registry = Path(path)
    errors: list[str] = []
    entries = load_registry(registry)
    seen_ids: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        quarantine_id = str(entry.get("quarantine_id", ""))
        if entry.get("schema_version") != 1:
            errors.append(f"entry {index}: unsupported schema_version")
        if not quarantine_id:
            errors.append(f"entry {index}: quarantine_id missing")
        elif quarantine_id in seen_ids:
            errors.append(f"entry {index}: duplicate quarantine_id")
        seen_ids.add(quarantine_id)
        if entry.get("state") != "quarantined":
            errors.append(f"entry {index}: unexpected state")
        if not str(entry.get("response_evidence_sha256", "")):
            errors.append(f"entry {index}: response_evidence_sha256 missing")
    summary = {
        "entry_count": len(entries),
        "registry_sha256": sha256_file(registry) if registry.exists() else "",
        "valid": not errors,
    }
    return not errors, errors, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Append or verify quarantine registry entries")
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add")
    add.add_argument("--registry", default=".abl/quarantine/registry.ndjson")
    add.add_argument("--component-type", required=True)
    add.add_argument("--component-id", required=True)
    add.add_argument("--reason", required=True)
    add.add_argument("--run-id", required=True)
    add.add_argument("--response-evidence", required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("--registry", default=".abl/quarantine/registry.ndjson")
    args = parser.parse_args(argv)

    try:
        if args.command == "add":
            entry = create_quarantine_entry(
                args.registry,
                component_type=args.component_type,
                component_id=args.component_id,
                reason=args.reason,
                source_run_id=args.run_id,
                response_evidence_path=args.response_evidence,
            )
            print(json.dumps(entry.to_dict(), indent=2, sort_keys=True))
            return 0
        ok, errors, summary = verify_registry(args.registry)
        print(json.dumps(summary, indent=2, sort_keys=True))
        for error in errors:
            print(f"ERROR: {error}")
        return 0 if ok else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
