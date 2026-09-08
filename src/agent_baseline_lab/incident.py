from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .evidence import sha256_file, verify_bundle
from .response import load_response_drill
from .response_link_verify import verify_response_link


@dataclass(frozen=True)
class IncidentSource:
    kind: str
    original_path: str
    copied_path: str
    sha256: str
    verified_before_copy: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IncidentBundleSummary:
    schema_version: int
    artifact_type: str
    incident_id: str
    created_at: str
    root: str
    sources: list[IncidentSource]
    source_count: int
    file_count: int
    manifest_sha256: str
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["sources"] = [item.to_dict() for item in self.sources]
        return payload


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _tree_sha256(path: Path) -> str:
    if path.is_file():
        return sha256_file(path)
    digest = hashlib.sha256()
    for item in sorted(path.rglob("*")):
        if not item.is_file():
            continue
        rel = item.relative_to(path).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(item).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _copy_source(source: Path, destination: Path) -> None:
    if source.is_dir():
        shutil.copytree(source, destination)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _verify_generic_json(path: Path) -> bool:
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return True


def _write_file_manifest(root: Path) -> Path:
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "incident-manifest.sha256.json":
            continue
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    manifest = root / "incident-manifest.sha256.json"
    manifest.write_text(
        json.dumps({"schema_version": 1, "algorithm": "sha256", "files": files}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def verify_incident_bundle(root: str | Path) -> tuple[bool, list[str], dict[str, Any]]:
    base = Path(root)
    manifest = base / "incident-manifest.sha256.json"
    if not manifest.exists():
        return False, ["incident manifest is missing"], {}
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, [f"incident manifest cannot be parsed: {exc}"], {}
    errors: list[str] = []
    for item in payload.get("files", []):
        path = base / str(item.get("path", ""))
        if not path.exists():
            errors.append(f"missing: {item.get('path')}")
            continue
        if sha256_file(path) != item.get("sha256"):
            errors.append(f"hash mismatch: {item.get('path')}")
    summary = {
        "manifest_sha256": sha256_file(manifest),
        "file_count": len(payload.get("files", [])),
    }
    return not errors, errors, summary


def build_incident_bundle(
    assessment_evidence: str | Path,
    *,
    output_root: str | Path = "incidents",
    response_evidence: str | Path | None = None,
    response_link: str | Path | None = None,
    agent_run: str | Path | None = None,
    fallback_evidence: str | Path | None = None,
    quarantine_registry: str | Path | None = None,
    additional_files: list[str | Path] | None = None,
) -> IncidentBundleSummary:
    assessment = Path(assessment_evidence).resolve()
    assessment_ok, assessment_errors, _ = verify_bundle(assessment)
    if not assessment_ok:
        raise ValueError("assessment evidence must verify before incident preservation: " + "; ".join(assessment_errors))

    response_path = Path(response_evidence).resolve() if response_evidence else None
    response_ok = True
    if response_path:
        response_payload, response_errors = load_response_drill(response_path)
        response_ok = response_payload is not None and not response_errors
        if not response_ok:
            raise ValueError("response evidence is invalid: " + "; ".join(response_errors))

    link_path = Path(response_link).resolve() if response_link else None
    link_ok = True
    if link_path:
        if response_path is None:
            raise ValueError("response_link requires response_evidence")
        link_ok, link_errors, _ = verify_response_link(link_path, assessment, response_path)
        if not link_ok:
            raise ValueError("response link must verify before incident preservation: " + "; ".join(link_errors))

    incident_id = "incident-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
    root = Path(output_root).resolve() / incident_id
    if root.exists():
        raise FileExistsError(f"incident directory already exists: {root}")
    sources_root = root / "sources"
    sources_root.mkdir(parents=True)
    sources: list[IncidentSource] = []

    def preserve(kind: str, source: Path, verified: bool) -> None:
        destination = sources_root / kind / source.name
        before = _tree_sha256(source)
        _copy_source(source, destination)
        after = _tree_sha256(destination)
        if before != after:
            raise RuntimeError(f"copy verification failed for {kind}")
        sources.append(
            IncidentSource(
                kind=kind,
                original_path=str(source),
                copied_path=str(destination.relative_to(root)),
                sha256=after,
                verified_before_copy=verified,
            )
        )

    preserve("assessment", assessment, assessment_ok)
    if response_path:
        preserve("response", response_path, response_ok)
    if link_path:
        preserve("response-link", link_path, link_ok)
    if agent_run:
        agent = Path(agent_run).resolve()
        if not agent.exists():
            raise FileNotFoundError(f"agent run not found: {agent}")
        preserve("agent-run", agent, (agent / "manifest.sha256.json").exists() if agent.is_dir() else _verify_generic_json(agent))
    for kind, optional in (
        ("fallback", fallback_evidence),
        ("quarantine", quarantine_registry),
    ):
        if optional:
            source = Path(optional).resolve()
            if not source.exists() or (source.is_file() and not _verify_generic_json(source)):
                raise ValueError(f"{kind} evidence is missing or invalid")
            preserve(kind, source, True)
    for index, value in enumerate(additional_files or [], start=1):
        source = Path(value).resolve()
        if not source.exists():
            raise FileNotFoundError(f"additional incident evidence not found: {source}")
        preserve(f"additional-{index}", source, False)

    metadata_path = root / "incident.json"
    metadata = {
        "schema_version": 1,
        "artifact_type": "incident-evidence-bundle",
        "incident_id": incident_id,
        "created_at": _utc_now(),
        "sources": [item.to_dict() for item in sources],
        "claims_boundary": (
            "This bundle preserves byte-identical copies and verification state at collection time. "
            "It does not make unverified source evidence trustworthy; externally signing the final "
            "incident manifest is required for authenticity outside this producer boundary."
        ),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = _write_file_manifest(root)
    ok, errors, verify_summary = verify_incident_bundle(root)
    if not ok:
        raise RuntimeError("incident bundle self-verification failed: " + "; ".join(errors))
    return IncidentBundleSummary(
        schema_version=1,
        artifact_type="incident-evidence-bundle-summary",
        incident_id=incident_id,
        created_at=metadata["created_at"],
        root=str(root),
        sources=sources,
        source_count=len(sources),
        file_count=int(verify_summary["file_count"]),
        manifest_sha256=sha256_file(manifest),
        claims_boundary=metadata["claims_boundary"],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build or verify evidence-preserving incident bundles")
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("assessment_evidence")
    build.add_argument("--output-root", default="incidents")
    build.add_argument("--response-evidence", default=None)
    build.add_argument("--response-link", default=None)
    build.add_argument("--agent-run", default=None)
    build.add_argument("--fallback", default=None)
    build.add_argument("--quarantine", default=None)
    build.add_argument("--additional", action="append", default=[])
    verify = sub.add_parser("verify")
    verify.add_argument("incident_root")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            summary = build_incident_bundle(
                args.assessment_evidence,
                output_root=args.output_root,
                response_evidence=args.response_evidence,
                response_link=args.response_link,
                agent_run=args.agent_run,
                fallback_evidence=args.fallback,
                quarantine_registry=args.quarantine,
                additional_files=args.additional,
            )
            print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
            return 0
        ok, errors, summary = verify_incident_bundle(args.incident_root)
        print(json.dumps(summary, indent=2, sort_keys=True))
        for error in errors:
            print(f"ERROR: {error}")
        return 0 if ok else 1
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
