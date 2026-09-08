from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .evidence import sha256_file


@dataclass(frozen=True)
class IncidentArtifact:
    role: str
    path: str
    sha256: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class IncidentBundle:
    schema_version: int
    incident_id: str
    created_at: str
    source_run_id: str
    artifacts: list[IncidentArtifact]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "incident_id": self.incident_id,
            "created_at": self.created_at,
            "source_run_id": self.source_run_id,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "claims_boundary": self.claims_boundary,
        }


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def create_incident_bundle(
    output_path: str | Path,
    *,
    source_run_id: str,
    artifacts: list[tuple[str, str | Path]],
) -> IncidentBundle:
    if not source_run_id.strip():
        raise ValueError("source_run_id is required")
    resolved: list[IncidentArtifact] = []
    seen_roles: set[str] = set()
    for role, raw_path in artifacts:
        if role in seen_roles:
            raise ValueError(f"duplicate incident artifact role: {role}")
        seen_roles.add(role)
        path = Path(raw_path)
        if not path.exists() or not path.is_file():
            raise ValueError(f"incident artifact is missing or not a file: {path}")
        resolved.append(
            IncidentArtifact(
                role=role,
                path=str(path),
                sha256=sha256_file(path),
            )
        )
    if not resolved:
        raise ValueError("incident bundle requires at least one artifact")

    created = _utc_now()
    compact = created.replace(":", "").replace("+00:00", "Z")
    bundle = IncidentBundle(
        schema_version=1,
        incident_id=f"incident-{compact}-{source_run_id}",
        created_at=created,
        source_run_id=source_run_id,
        artifacts=resolved,
        claims_boundary=(
            "This manifest preserves digest-level relationships among incident artifacts. "
            "It does not copy secrets, assert root cause, or prove authenticity unless the manifest itself is externally signed or anchored."
        ),
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(bundle.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return bundle


def verify_incident_bundle(path: str | Path) -> tuple[bool, list[str], dict[str, Any]]:
    bundle_path = Path(path)
    payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if payload.get("schema_version") != 1:
        errors.append("unsupported incident bundle schema_version")
    artifacts = payload.get("artifacts", [])
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("incident bundle contains no artifacts")
        artifacts = []
    verified = 0
    roles: set[str] = set()
    for index, artifact in enumerate(artifacts, start=1):
        if not isinstance(artifact, dict):
            errors.append(f"artifact {index}: malformed entry")
            continue
        role = str(artifact.get("role", ""))
        if not role or role in roles:
            errors.append(f"artifact {index}: missing or duplicate role")
        roles.add(role)
        artifact_path = Path(str(artifact.get("path", "")))
        expected = str(artifact.get("sha256", ""))
        if not artifact_path.exists():
            errors.append(f"artifact {index}: missing path {artifact_path}")
            continue
        if sha256_file(artifact_path) != expected:
            errors.append(f"artifact {index}: digest mismatch for role {role}")
            continue
        verified += 1
    summary = {
        "incident_id": payload.get("incident_id"),
        "source_run_id": payload.get("source_run_id"),
        "artifact_count": len(artifacts),
        "verified_artifact_count": verified,
        "bundle_sha256": sha256_file(bundle_path),
        "valid": not errors,
    }
    return not errors, errors, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create or verify an evidence-preserving incident bundle")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--output", required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="ROLE=PATH",
        help="artifact role and path; repeat for multiple artifacts",
    )
    verify = sub.add_parser("verify")
    verify.add_argument("bundle")
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            pairs: list[tuple[str, str]] = []
            for value in args.artifact:
                if "=" not in value:
                    raise ValueError("--artifact must use ROLE=PATH")
                role, file_path = value.split("=", 1)
                pairs.append((role, file_path))
            bundle = create_incident_bundle(args.output, source_run_id=args.run_id, artifacts=pairs)
            print(json.dumps(bundle.to_dict(), indent=2, sort_keys=True))
            return 0
        ok, errors, summary = verify_incident_bundle(args.bundle)
        print(json.dumps(summary, indent=2, sort_keys=True))
        for error in errors:
            print(f"ERROR: {error}")
        return 0 if ok else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
