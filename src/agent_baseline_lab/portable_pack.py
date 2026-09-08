from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .evidence import sha256_file, verify_bundle
from .privacy import find_local_path_markers
from .signing import verify_signature


@dataclass(frozen=True)
class PackFile:
    path: str
    role: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LinkedIncidentArtifact:
    role: str
    archive_path: str
    sha256: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class PackSummary:
    schema_version: int
    source_run_id: str
    files: list[PackFile]
    linked_incident_artifacts: list[LinkedIncidentArtifact]
    excluded_categories: list[str]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source_run_id": self.source_run_id,
            "files": [item.to_dict() for item in self.files],
            "linked_incident_artifacts": [item.to_dict() for item in self.linked_incident_artifacts],
            "excluded_categories": self.excluded_categories,
            "claims_boundary": self.claims_boundary,
        }


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _latest_evidence(root: Path) -> Path:
    candidates = [path for path in (root / "evidence").glob("abl-*") if path.is_dir()]
    if not candidates:
        raise ValueError("no assessment evidence bundle found")
    return max(candidates, key=lambda path: path.stat().st_mtime)


def _safe_relative(root: Path, path: Path) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"refusing to export path outside project root: {path}") from exc
    if path.is_symlink():
        raise ValueError(f"refusing to export symlink: {path}")
    return relative


def _validate_archive_path(archive: str) -> str:
    pure = PurePosixPath(archive)
    if pure.is_absolute() or ".." in pure.parts or not archive:
        raise ValueError(f"unsafe archive path: {archive}")
    return pure.as_posix()


def _zip_write(zf: zipfile.ZipFile, archive_path: str, data: bytes) -> None:
    info = zipfile.ZipInfo(archive_path, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    zf.writestr(info, data)


def _report_candidates(root: Path, run_id: str) -> list[Path]:
    # The incident bundle is intentionally excluded here and rewritten below with
    # archive-relative paths so host filesystem paths are never exported.
    names = [
        f"{run_id}.json",
        f"{run_id}.html",
        f"{run_id}.attestation.json",
        f"{run_id}.attestation.json.ed25519.json",
        f"{run_id}.response-link.json",
        f"{run_id}.interview-demo.json",
        f"{run_id}.audit-correlation.json",
        f"{run_id}.evidence-matrix.json",
    ]
    return [root / "reports" / name for name in names]


def _assurance_matches(root: Path, run_id: str) -> Path | None:
    path = root / "reports" / "assurance-summary.json"
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return path if payload.get("assessment_run_id") == run_id else None


def create_pack(
    root_path: str | Path = ".",
    *,
    output_path: str | Path,
    run_id: str | None = None,
) -> tuple[Path, PackSummary]:
    root = Path(root_path).resolve()
    evidence_dir = root / "evidence" / run_id if run_id else _latest_evidence(root)
    if not evidence_dir.is_dir():
        raise ValueError(f"assessment evidence bundle not found: {evidence_dir}")
    run_id = evidence_dir.name

    bundle_ok, bundle_errors, _ = verify_bundle(evidence_dir)
    if not bundle_ok:
        raise ValueError("refusing to export invalid assessment bundle: " + "; ".join(bundle_errors))

    entries: dict[str, tuple[bytes, str]] = {}

    def add_bytes(archive_path: str, data: bytes, role: str) -> str:
        archive = _validate_archive_path(archive_path)
        leaked_markers = find_local_path_markers(data, root)
        if leaked_markers:
            raise ValueError(
                f"refusing to export local filesystem path marker in {archive}; "
                "persist evidence-safe relative references before customer handoff"
            )
        if archive in entries and entries[archive] != (data, role):
            raise ValueError(f"duplicate archive path: {archive}")
        entries[archive] = (data, role)
        return archive

    def add_file(path: Path, role: str, archive_path: str | None = None) -> str:
        if not path.exists() or not path.is_file():
            raise ValueError(f"pack source file is missing: {path}")
        relative = _safe_relative(root, path)
        archive = archive_path or relative.as_posix()
        return add_bytes(archive, path.read_bytes(), role)

    for path in sorted(evidence_dir.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"refusing to export symlink from evidence bundle: {path}")
        if path.is_file():
            add_file(path, "assessment-evidence")

    for report in _report_candidates(root, run_id):
        if report.exists():
            add_file(report, "report")

    assurance = _assurance_matches(root, run_id)
    if assurance is not None:
        add_file(assurance, "assurance-summary")

    public_key = root / ".abl" / "keys" / "attestation-public.json"
    if public_key.exists():
        add_file(public_key, "public-verification-key", "trust/attestation-public.json")

    registry = root / ".abl" / "quarantine" / "registry.ndjson"
    if registry.exists():
        add_file(registry, "quarantine-registry")

    linked: list[LinkedIncidentArtifact] = []
    incident_path = root / "reports" / f"{run_id}.incident.json"
    if incident_path.exists():
        incident = json.loads(incident_path.read_text(encoding="utf-8"))
        if incident.get("source_run_id") != run_id:
            raise ValueError("incident bundle source_run_id does not match selected assessment")
        artifacts = incident.get("artifacts", [])
        if not isinstance(artifacts, list):
            raise ValueError("incident bundle artifacts must be a list")

        portable_artifacts: list[dict[str, str]] = []
        seen_roles: set[str] = set()
        for item in artifacts:
            if not isinstance(item, dict):
                raise ValueError("incident bundle contains malformed artifact entry")
            role = str(item.get("role", "")).strip()
            if not role or role in seen_roles:
                raise ValueError("incident bundle contains missing or duplicate artifact role")
            seen_roles.add(role)
            source = Path(str(item.get("path", "")))
            if not source.is_absolute():
                source = root / source
            expected = str(item.get("sha256", ""))
            if not source.exists() or not source.is_file():
                raise ValueError(f"incident artifact is unavailable for portable export: {source}")
            _safe_relative(root, source)
            observed = sha256_file(source)
            if observed != expected:
                raise ValueError(f"incident artifact digest mismatch before export: {role}")
            archive = add_file(source, f"incident-artifact:{role}")
            linked.append(
                LinkedIncidentArtifact(
                    role=role,
                    archive_path=archive,
                    sha256=observed,
                )
            )
            portable_artifacts.append(
                {
                    "role": role,
                    "path": archive,
                    "sha256": observed,
                }
            )

        portable_incident = {
            "schema_version": 1,
            "portable": True,
            "incident_id": incident.get("incident_id"),
            "created_at": incident.get("created_at"),
            "source_run_id": run_id,
            "artifacts": portable_artifacts,
            "claims_boundary": (
                "Portable incident manifest. Artifact paths are ZIP-member paths, not host paths. "
                "Digest validity preserves evidence linkage but does not establish root cause or external authenticity."
            ),
        }
        add_bytes(
            f"reports/{run_id}.incident.json",
            (json.dumps(portable_incident, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            "portable-incident-manifest",
        )

    if any(name.endswith("attestation-private.json") for name in entries):
        raise ValueError("private signing key must never be included in a portable pack")

    files = [
        PackFile(
            path=archive,
            role=role,
            sha256=_sha256_bytes(data),
            size=len(data),
        )
        for archive, (data, role) in sorted(entries.items())
    ]

    summary = PackSummary(
        schema_version=1,
        source_run_id=run_id,
        files=files,
        linked_incident_artifacts=linked,
        excluded_categories=[
            "private signing keys",
            "agent-runs raw execution capsules",
            "host filesystem paths from incident manifests",
            "local project/home path prefixes",
            "unreferenced local .abl state",
        ],
        claims_boundary=(
            "This portable pack preserves and verifies shareable evidence for one assessment run. "
            "Creation fails closed if selected artifacts still contain the local project or home path. "
            "Its internal manifest is not itself an external trust anchor. Pin or sign the final ZIP digest "
            "through an independent channel when authenticity of the handoff matters."
        ),
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as zf:
        for item in files:
            data, _ = entries[item.path]
            _zip_write(zf, item.path, data)
        manifest_bytes = (
            json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        _zip_write(zf, "pack-manifest.json", manifest_bytes)
    return output, summary


def _validate_zip_name(name: str) -> None:
    _validate_archive_path(name)


def _verify_portable_incident(
    zf: zipfile.ZipFile,
    *,
    run_id: str,
    names: set[str],
) -> list[str]:
    errors: list[str] = []
    incident_name = f"reports/{run_id}.incident.json"
    if incident_name not in names:
        return errors
    try:
        incident = json.loads(zf.read(incident_name).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"portable incident manifest is unreadable: {exc}"]
    if incident.get("schema_version") != 1 or incident.get("portable") is not True:
        errors.append("portable incident manifest schema/portable marker is invalid")
    if incident.get("source_run_id") != run_id:
        errors.append("portable incident source_run_id mismatch")
    artifacts = incident.get("artifacts", [])
    if not isinstance(artifacts, list):
        return [*errors, "portable incident artifacts must be a list"]
    seen_roles: set[str] = set()
    for index, item in enumerate(artifacts, start=1):
        if not isinstance(item, dict):
            errors.append(f"portable incident artifact {index}: malformed entry")
            continue
        role = str(item.get("role", ""))
        member = str(item.get("path", ""))
        expected = str(item.get("sha256", ""))
        if not role or role in seen_roles:
            errors.append(f"portable incident artifact {index}: missing or duplicate role")
        seen_roles.add(role)
        try:
            _validate_zip_name(member)
        except ValueError as exc:
            errors.append(f"portable incident artifact {index}: {exc}")
            continue
        if member not in names:
            errors.append(f"portable incident artifact {index}: missing ZIP member {member}")
            continue
        if _sha256_bytes(zf.read(member)) != expected:
            errors.append(f"portable incident artifact {index}: digest mismatch for {role}")
    return errors


def verify_pack(path: str | Path) -> tuple[bool, list[str], dict[str, Any]]:
    pack = Path(path)
    errors: list[str] = []
    details: dict[str, Any] = {}
    try:
        with zipfile.ZipFile(pack, "r") as zf:
            names_list = zf.namelist()
            names = set(names_list)
            if len(names_list) != len(names):
                errors.append("ZIP contains duplicate member names")
            for name in names_list:
                _validate_zip_name(name)
            if "pack-manifest.json" not in names:
                return False, ["pack-manifest.json is missing"], {}
            manifest = json.loads(zf.read("pack-manifest.json").decode("utf-8"))
            if manifest.get("schema_version") != 1:
                errors.append("unsupported portable-pack schema_version")
            run_id = str(manifest.get("source_run_id", ""))
            entries = manifest.get("files", [])
            if not run_id:
                errors.append("source_run_id is missing")
            if not isinstance(entries, list):
                errors.append("manifest files must be a list")
                entries = []
            expected_names = {"pack-manifest.json"}
            verified = 0
            for index, item in enumerate(entries, start=1):
                if not isinstance(item, dict):
                    errors.append(f"file {index}: malformed manifest entry")
                    continue
                member = str(item.get("path", ""))
                _validate_zip_name(member)
                expected_names.add(member)
                if member not in names:
                    errors.append(f"file {index}: missing ZIP member {member}")
                    continue
                data = zf.read(member)
                if _sha256_bytes(data) != str(item.get("sha256", "")):
                    errors.append(f"file {index}: digest mismatch for {member}")
                    continue
                if len(data) != int(item.get("size", -1)):
                    errors.append(f"file {index}: size mismatch for {member}")
                    continue
                verified += 1
            unexpected = sorted(names - expected_names)
            if unexpected:
                errors.append("ZIP contains unmanifested members: " + ", ".join(unexpected))
            if any(name.endswith("attestation-private.json") for name in names):
                errors.append("portable pack contains a forbidden private signing key")

            linked = manifest.get("linked_incident_artifacts", [])
            if isinstance(linked, list):
                for index, item in enumerate(linked, start=1):
                    if not isinstance(item, dict):
                        errors.append(f"linked incident artifact {index}: malformed entry")
                        continue
                    if "source_path" in item:
                        errors.append(f"linked incident artifact {index}: host source_path must not be exported")
                    archive = str(item.get("archive_path", ""))
                    if archive not in names:
                        errors.append(f"linked incident artifact {index}: missing {archive}")
                        continue
                    if _sha256_bytes(zf.read(archive)) != str(item.get("sha256", "")):
                        errors.append(f"linked incident artifact {index}: digest mismatch")

            errors.extend(_verify_portable_incident(zf, run_id=run_id, names=names))

            with tempfile.TemporaryDirectory(prefix="abl-portable-pack-") as temp_dir:
                temp = Path(temp_dir)
                for name in expected_names:
                    if name == "pack-manifest.json":
                        continue
                    target = temp / Path(*PurePosixPath(name).parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(zf.read(name))
                embedded_evidence_dir = temp / "evidence" / run_id
                bundle_ok, bundle_errors, bundle_summary = verify_bundle(embedded_evidence_dir)
                if not bundle_ok:
                    errors.extend(f"embedded evidence: {error}" for error in bundle_errors)

                attestation = temp / "reports" / f"{run_id}.attestation.json"
                signature = temp / "reports" / f"{run_id}.attestation.json.ed25519.json"
                public_key = temp / "trust" / "attestation-public.json"
                signature_summary: dict[str, Any] | None = None
                if attestation.exists() and signature.exists():
                    signature_ok, signature_errors, signature_summary = verify_signature(
                        attestation,
                        signature,
                        public_key_path=public_key if public_key.exists() else None,
                    )
                    if not signature_ok:
                        errors.extend(f"embedded signature: {error}" for error in signature_errors)

            details = {
                "source_run_id": run_id,
                "file_count": len(entries),
                "verified_file_count": verified,
                "pack_sha256": sha256_file(pack),
                "embedded_evidence": bundle_summary,
                "embedded_signature": signature_summary,
                "external_pack_anchor_supplied": False,
            }
    except (OSError, ValueError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        return False, [f"portable pack cannot be verified: {exc}"], {}
    details["valid"] = not errors
    return not errors, errors, details


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create or verify a portable customer evidence pack")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create")
    create.add_argument("--root", default=".")
    create.add_argument("--run-id", default=None)
    create.add_argument("--output", required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("pack")

    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            output, summary = create_pack(
                args.root,
                output_path=args.output,
                run_id=args.run_id,
            )
            print(
                json.dumps(
                    {
                        **summary.to_dict(),
                        "pack": str(output),
                        "pack_sha256": sha256_file(output),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        ok, errors, summary = verify_pack(args.pack)
        print(json.dumps(summary, indent=2, sort_keys=True))
        for error in errors:
            print(f"ERROR: {error}")
        return 0 if ok else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
