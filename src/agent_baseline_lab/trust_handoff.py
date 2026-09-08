from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .portable_pack import verify_pack
from .privacy import find_local_path_markers, sanitize_value
from .signing import verify_signature


@dataclass(frozen=True)
class HandoffFile:
    path: str
    role: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HandoffSummary:
    schema_version: int
    source_run_id: str
    dry_run: bool
    files: list[HandoffFile]
    excluded_categories: list[str]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source_run_id": self.source_run_id,
            "dry_run": self.dry_run,
            "files": [item.to_dict() for item in self.files],
            "excluded_categories": self.excluded_categories,
            "claims_boundary": self.claims_boundary,
        }


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_archive_path(value: str) -> str:
    pure = PurePosixPath(value)
    if not value or pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe handoff archive path: {value}")
    return pure.as_posix()


def _zip_write(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    zf.writestr(info, data)


def _inside_root(root: Path, path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"refusing to export file outside project root: {path}") from exc
    if path.is_symlink():
        raise ValueError(f"refusing to export symlink: {path}")
    if not path.is_file():
        raise ValueError(f"handoff source is missing: {path}")
    return resolved


def write_portable_json(
    source: str | Path,
    *,
    root_path: str | Path = ".",
    output: str | Path,
) -> Path:
    """Write a deterministic JSON copy with project/home prefixes redacted.

    The portable copy is a distinct artifact and must be signed separately if authenticity
    matters. This avoids invalidating signatures on the original source by silently rewriting it.
    """
    root = Path(root_path).resolve()
    source_path = Path(source)
    if not source_path.is_absolute():
        source_path = root / source_path
    _inside_root(root, source_path)
    try:
        payload = json.loads(source_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"portable JSON source is invalid: {source_path}: {exc}") from exc
    portable = sanitize_value(payload, root)
    output_path = Path(output)
    if not output_path.is_absolute():
        output_path = root / output_path
    _inside_parent = output_path.parent.resolve()
    try:
        _inside_parent.relative_to(root)
    except ValueError as exc:
        raise ValueError("portable JSON output must stay inside project root") from exc
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(portable, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if find_local_path_markers(data, root):
        raise ValueError("portable JSON still contains a local filesystem path marker")
    output_path.write_bytes(data)
    return output_path


def create_handoff_pack(
    root_path: str | Path,
    *,
    run_id: str,
    output_path: str | Path,
    dry_run: bool,
    sources: list[tuple[str, str | Path, str]],
) -> tuple[Path, HandoffSummary]:
    root = Path(root_path).resolve()
    entries: dict[str, tuple[bytes, str]] = {}

    def add(role: str, source: str | Path, archive_path: str) -> None:
        source_path = Path(source)
        if not source_path.is_absolute():
            source_path = root / source_path
        _inside_root(root, source_path)
        archive = _safe_archive_path(archive_path)
        if archive.endswith("attestation-private.json") or "private-key" in archive:
            raise ValueError("private signing material is forbidden in a customer trust handoff")
        if archive.endswith("image.oci.tar") or archive.endswith(".oci.tar"):
            raise ValueError("OCI image archives are intentionally excluded from the customer handoff")
        data = source_path.read_bytes()
        leaked = find_local_path_markers(data, root)
        if leaked:
            raise ValueError(
                f"refusing to export local filesystem path marker in {archive}; "
                "create a portable/sanitized artifact first"
            )
        if archive in entries:
            raise ValueError(f"duplicate handoff archive path: {archive}")
        entries[archive] = (data, role)

    for role, source, archive in sources:
        add(role, source, archive)

    files = [
        HandoffFile(
            path=archive,
            role=role,
            sha256=_sha256_bytes(data),
            size=len(data),
        )
        for archive, (data, role) in sorted(entries.items())
    ]
    summary = HandoffSummary(
        schema_version=1,
        source_run_id=run_id,
        dry_run=dry_run,
        files=files,
        excluded_categories=[
            "private signing keys",
            "raw agent prompts and stdout/stderr",
            "host filesystem paths",
            "Docker credentials and local Docker state",
            "OCI image archive and binary layers",
            "unreferenced local .abl state",
        ],
        claims_boundary=(
            "This handoff packages portable decision, assurance, lineage and trust evidence plus their "
            "verification material. The OCI image archive is deliberately excluded; its SHA-256 and verified "
            "attestation/graph findings remain recorded in the included trusted-artifact and lineage evidence. "
            "The handoff verifier checks internal integrity and nested signatures where present; it does not "
            "rebuild the image, establish key-owner identity, or constitute Docker/compliance certification."
        ),
    )

    output = Path(output_path)
    if not output.is_absolute():
        output = root / output
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as zf:
        for item in files:
            data, _ = entries[item.path]
            _zip_write(zf, item.path, data)
        manifest = (json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8")
        _zip_write(zf, "handoff-manifest.json", manifest)
    return output, summary


def _role_map(manifest: dict[str, Any]) -> dict[str, str]:
    role_map: dict[str, str] = {}
    for item in manifest.get("files", []):
        if not isinstance(item, dict):
            continue
        role = str(item.get("role", ""))
        path = str(item.get("path", ""))
        if role and path:
            if role in role_map:
                raise ValueError(f"duplicate handoff role: {role}")
            role_map[role] = path
    return role_map


def verify_handoff_pack(path: str | Path) -> tuple[bool, list[str], dict[str, Any]]:
    pack = Path(path)
    errors: list[str] = []
    details: dict[str, Any] = {}
    try:
        with zipfile.ZipFile(pack, "r") as zf:
            names_list = zf.namelist()
            names = set(names_list)
            if len(names_list) != len(names):
                errors.append("handoff ZIP contains duplicate member names")
            for name in names_list:
                _safe_archive_path(name)
                if name.endswith("attestation-private.json") or "private-key" in name:
                    errors.append(f"forbidden private signing material: {name}")
                if name.endswith("image.oci.tar") or name.endswith(".oci.tar"):
                    errors.append(f"forbidden OCI image archive: {name}")
            if "handoff-manifest.json" not in names:
                return False, ["handoff-manifest.json is missing"], {}
            manifest = json.loads(zf.read("handoff-manifest.json").decode("utf-8"))
            if manifest.get("schema_version") != 1:
                errors.append("unsupported handoff schema_version")
            entries = manifest.get("files", [])
            if not isinstance(entries, list):
                entries = []
                errors.append("handoff manifest files must be a list")
            expected = {"handoff-manifest.json"}
            verified = 0
            for index, item in enumerate(entries, start=1):
                if not isinstance(item, dict):
                    errors.append(f"handoff file {index}: malformed manifest entry")
                    continue
                member = _safe_archive_path(str(item.get("path", "")))
                expected.add(member)
                if member not in names:
                    errors.append(f"handoff file {index}: missing ZIP member {member}")
                    continue
                data = zf.read(member)
                if _sha256_bytes(data) != str(item.get("sha256", "")):
                    errors.append(f"handoff file {index}: digest mismatch for {member}")
                    continue
                if len(data) != int(item.get("size", -1)):
                    errors.append(f"handoff file {index}: size mismatch for {member}")
                    continue
                verified += 1
            unexpected = sorted(names - expected)
            if unexpected:
                errors.append("handoff ZIP contains unmanifested members: " + ", ".join(unexpected))

            roles = _role_map(manifest)
            details["source_run_id"] = str(manifest.get("source_run_id", ""))
            details["dry_run"] = bool(manifest.get("dry_run", False))
            details["verified_files"] = verified
            details["roles"] = sorted(roles)

            golden_pack = roles.get("golden-customer-pack")
            if golden_pack and golden_pack in names:
                with tempfile.TemporaryDirectory(prefix="abl-handoff-") as tmp:
                    tmp_root = Path(tmp)
                    nested = tmp_root / "customer-evidence-pack.zip"
                    nested.write_bytes(zf.read(golden_pack))
                    nested_ok, nested_errors, _ = verify_pack(nested)
                    if not nested_ok:
                        errors.extend(f"nested customer pack: {error}" for error in nested_errors)
                    details["nested_customer_pack_verified"] = nested_ok

                    sig_member = roles.get("golden-customer-pack-signature")
                    key_member = roles.get("public-verification-key")
                    if sig_member and key_member and sig_member in names and key_member in names:
                        signature = tmp_root / "customer-evidence-pack.zip.ed25519.json"
                        public_key = tmp_root / "attestation-public.json"
                        signature.write_bytes(zf.read(sig_member))
                        public_key.write_bytes(zf.read(key_member))
                        sig_ok, sig_errors, _ = verify_signature(
                            nested,
                            signature,
                            public_key_path=public_key,
                        )
                        if not sig_ok:
                            errors.extend(
                                f"nested customer pack signature: {error}" for error in sig_errors
                            )
                        details["nested_customer_pack_signature_verified"] = sig_ok

            lineage = roles.get("agent-artifact-lineage")
            lineage_sig = roles.get("agent-artifact-lineage-signature")
            public_key = roles.get("public-verification-key")
            if lineage and lineage_sig and public_key:
                with tempfile.TemporaryDirectory(prefix="abl-lineage-") as tmp:
                    tmp_root = Path(tmp)
                    subject = tmp_root / "agent-artifact-lineage.json"
                    signature = tmp_root / "agent-artifact-lineage.ed25519.json"
                    key = tmp_root / "attestation-public.json"
                    subject.write_bytes(zf.read(lineage))
                    signature.write_bytes(zf.read(lineage_sig))
                    key.write_bytes(zf.read(public_key))
                    lineage_ok, lineage_errors, _ = verify_signature(
                        subject,
                        signature,
                        public_key_path=key,
                    )
                    if not lineage_ok:
                        errors.extend(f"lineage signature: {error}" for error in lineage_errors)
                    details["lineage_signature_verified"] = lineage_ok
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        errors.append(str(exc))
    details["pack_sha256"] = _sha256_bytes(pack.read_bytes()) if pack.is_file() else ""
    return not errors, errors, details


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a customer trust handoff ZIP")
    parser.add_argument("handoff")
    args = parser.parse_args(argv)
    ok, errors, details = verify_handoff_pack(args.handoff)
    print(json.dumps(details, indent=2, sort_keys=True))
    for error in errors:
        print(f"ERROR: {error}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
