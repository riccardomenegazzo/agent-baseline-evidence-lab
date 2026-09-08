from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class QuarantineEvent:
    schema_version: int
    event_id: str
    component_id: str
    component_type: str
    action: str
    reason: str
    source_evidence_sha256: str
    actor: str
    at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_registry(path: str | Path) -> dict[str, Any]:
    registry = Path(path)
    if not registry.exists():
        return {
            "schema_version": 1,
            "artifact_type": "component-quarantine-registry",
            "events": [],
            "claims_boundary": (
                "Registry records quarantine decisions and evidence links. It does not by itself prove "
                "that a runtime component was technically isolated; live containment evidence is separate."
            ),
        }
    payload = json.loads(registry.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1 or payload.get("artifact_type") != "component-quarantine-registry":
        raise ValueError("unsupported quarantine registry schema")
    if not isinstance(payload.get("events"), list):
        raise ValueError("quarantine registry events must be a list")
    return payload


def append_event(
    registry_path: str | Path,
    *,
    component_id: str,
    component_type: str,
    action: str,
    reason: str,
    actor: str,
    source_evidence: str | Path | None = None,
    source_evidence_sha256: str | None = None,
) -> QuarantineEvent:
    if action not in {"quarantine", "release"}:
        raise ValueError("action must be quarantine or release")
    if not component_id.strip() or not component_type.strip():
        raise ValueError("component_id and component_type are required")
    source_hash = source_evidence_sha256 or ""
    if source_evidence is not None:
        source_hash = _sha256_file(source_evidence)
    if not source_hash:
        raise ValueError("source evidence hash is required")

    payload = load_registry(registry_path)
    event = QuarantineEvent(
        schema_version=1,
        event_id=f"quarantine-{secrets.token_hex(8)}",
        component_id=component_id,
        component_type=component_type,
        action=action,
        reason=reason,
        source_evidence_sha256=source_hash,
        actor=actor,
        at=_utc_now(),
    )
    payload["events"].append(event.to_dict())
    path = Path(registry_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return event


def current_states(registry_path: str | Path) -> dict[str, dict[str, Any]]:
    payload = load_registry(registry_path)
    states: dict[str, dict[str, Any]] = {}
    for event in payload["events"]:
        component_id = str(event.get("component_id", ""))
        if component_id:
            states[component_id] = {
                "component_type": event.get("component_type"),
                "state": "quarantined" if event.get("action") == "quarantine" else "released",
                "reason": event.get("reason"),
                "source_evidence_sha256": event.get("source_evidence_sha256"),
                "event_id": event.get("event_id"),
                "at": event.get("at"),
            }
    return states


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Append-only component quarantine registry")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("quarantine", "release"):
        cmd = sub.add_parser(name)
        cmd.add_argument("component_id")
        cmd.add_argument("--type", required=True, dest="component_type")
        cmd.add_argument("--reason", required=True)
        cmd.add_argument("--actor", default="operator")
        cmd.add_argument("--evidence", default=None)
        cmd.add_argument("--evidence-sha256", default=None)
        cmd.add_argument("--registry", default=".abl/quarantine.json")
    show = sub.add_parser("show")
    show.add_argument("--registry", default=".abl/quarantine.json")
    args = parser.parse_args(argv)
    try:
        if args.command == "show":
            print(json.dumps(current_states(args.registry), indent=2, sort_keys=True))
            return 0
        event = append_event(
            args.registry,
            component_id=args.component_id,
            component_type=args.component_type,
            action=args.command,
            reason=args.reason,
            actor=args.actor,
            source_evidence=args.evidence,
            source_evidence_sha256=args.evidence_sha256,
        )
        print(json.dumps(event.to_dict(), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
