from __future__ import annotations

import hashlib
import json
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any


@dataclass(frozen=True)
class BlobVerification:
    digest: str
    declared_size: int | None
    observed_size: int
    digest_matches: bool
    size_matches: bool
    media_type: str
    role: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _blob_name(digest: str) -> str:
    algorithm, separator, value = digest.partition(":")
    if separator != ":" or algorithm != "sha256" or len(value) != 64:
        raise ValueError(f"unsupported OCI digest: {digest}")
    return f"blobs/sha256/{value}"


def _json_bytes(tf: tarfile.TarFile, member_name: str, max_bytes: int = 32 * 1024 * 1024) -> dict[str, Any]:
    try:
        member = tf.getmember(member_name)
    except KeyError as exc:
        raise ValueError(f"missing OCI member: {member_name}") from exc
    if not member.isfile():
        raise ValueError(f"OCI JSON member is not a regular file: {member_name}")
    if member.size > max_bytes:
        raise ValueError(f"OCI JSON member is unexpectedly large: {member_name}")
    stream = tf.extractfile(member)
    if stream is None:
        raise ValueError(f"OCI JSON member cannot be read: {member_name}")
    try:
        payload = json.loads(stream.read())
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid OCI JSON member {member_name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"OCI JSON member is not an object: {member_name}")
    return payload


def _verify_descriptor(
    tf: tarfile.TarFile,
    descriptor: dict[str, Any],
    *,
    role: str,
) -> BlobVerification:
    digest = str(descriptor.get("digest", ""))
    name = _blob_name(digest)
    try:
        member = tf.getmember(name)
    except KeyError as exc:
        raise ValueError(f"referenced OCI blob is missing: {digest}") from exc
    if not member.isfile():
        raise ValueError(f"referenced OCI blob is not a regular file: {digest}")
    stream = tf.extractfile(member)
    if stream is None:
        raise ValueError(f"referenced OCI blob cannot be read: {digest}")
    hasher = hashlib.sha256()
    observed_size = 0
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        observed_size += len(chunk)
        hasher.update(chunk)
    observed_digest = hasher.hexdigest()
    expected_digest = digest.split(":", 1)[1]
    declared_size = descriptor.get("size")
    declared_int = declared_size if isinstance(declared_size, int) else None
    verification = BlobVerification(
        digest=digest,
        declared_size=declared_int,
        observed_size=observed_size,
        digest_matches=observed_digest == expected_digest,
        size_matches=declared_int is None or declared_int == observed_size,
        media_type=str(descriptor.get("mediaType", "")),
        role=role,
    )
    if not verification.digest_matches:
        raise ValueError(f"OCI blob digest mismatch for {digest}")
    if not verification.size_matches:
        raise ValueError(
            f"OCI blob size mismatch for {digest}: declared {declared_int}, observed {observed_size}"
        )
    return verification


def _manifest_payload(tf: tarfile.TarFile, descriptor: dict[str, Any]) -> dict[str, Any]:
    return _json_bytes(tf, _blob_name(str(descriptor.get("digest", ""))))


def verify_oci_layout_integrity(archive: str | Path) -> tuple[bool, list[str], dict[str, Any]]:
    archive_path = Path(archive)
    errors: list[str] = []
    verified: list[BlobVerification] = []
    referenced: set[str] = set()
    summary: dict[str, Any] = {
        "archive": str(archive_path),
        "layout_version": "",
        "verified_blobs": [],
        "referenced_blob_count": 0,
        "verified_blob_count": 0,
        "unreferenced_blob_count": 0,
        "duplicate_members": [],
    }
    if not archive_path.is_file():
        return False, ["OCI archive is missing"], summary

    try:
        with tarfile.open(archive_path, "r:*") as tf:
            members = tf.getmembers()
            names = [member.name for member in members]
            duplicates = sorted({name for name in names if names.count(name) > 1})
            summary["duplicate_members"] = duplicates
            if duplicates:
                errors.append("OCI archive contains duplicate member names: " + ", ".join(duplicates))
                return False, errors, summary
            for member in members:
                pure = PurePosixPath(member.name)
                if pure.is_absolute() or ".." in pure.parts:
                    errors.append(f"unsafe OCI archive member path: {member.name}")
            if errors:
                return False, errors, summary

            layout = _json_bytes(tf, "oci-layout")
            layout_version = str(layout.get("imageLayoutVersion", ""))
            summary["layout_version"] = layout_version
            if layout_version != "1.0.0":
                errors.append(f"unsupported OCI layout version: {layout_version}")

            index = _json_bytes(tf, "index.json")
            if index.get("schemaVersion") != 2:
                errors.append("OCI index schemaVersion must be 2")
            manifests = index.get("manifests", [])
            if not isinstance(manifests, list) or not manifests:
                errors.append("OCI index must contain at least one manifest descriptor")
                return False, errors, summary

            for index_number, descriptor in enumerate(manifests):
                if not isinstance(descriptor, dict):
                    errors.append(f"OCI index descriptor {index_number} is not an object")
                    continue
                try:
                    top = _verify_descriptor(tf, descriptor, role="index-manifest")
                    verified.append(top)
                    referenced.add(top.digest)
                    manifest = _manifest_payload(tf, descriptor)
                except ValueError as exc:
                    errors.append(str(exc))
                    continue
                if manifest.get("schemaVersion") != 2:
                    errors.append(f"OCI manifest {top.digest} schemaVersion must be 2")

                config = manifest.get("config")
                if isinstance(config, dict) and config.get("digest"):
                    try:
                        item = _verify_descriptor(tf, config, role="manifest-config")
                        verified.append(item)
                        referenced.add(item.digest)
                    except ValueError as exc:
                        errors.append(str(exc))
                elif config is not None:
                    errors.append(f"OCI manifest {top.digest} contains an invalid config descriptor")

                layers = manifest.get("layers", [])
                if not isinstance(layers, list):
                    errors.append(f"OCI manifest {top.digest} layers must be an array")
                    continue
                for layer_number, layer in enumerate(layers):
                    if not isinstance(layer, dict):
                        errors.append(f"OCI manifest {top.digest} layer {layer_number} is not an object")
                        continue
                    try:
                        item = _verify_descriptor(tf, layer, role="manifest-layer")
                        verified.append(item)
                        referenced.add(item.digest)
                    except ValueError as exc:
                        errors.append(str(exc))

            blob_names = {
                member.name
                for member in members
                if member.isfile() and member.name.startswith("blobs/sha256/")
            }
            referenced_names = {_blob_name(digest) for digest in referenced}
            summary["referenced_blob_count"] = len(referenced)
            summary["verified_blob_count"] = len({item.digest for item in verified})
            summary["unreferenced_blob_count"] = len(blob_names - referenced_names)
            summary["verified_blobs"] = [item.to_dict() for item in verified]
    except (OSError, tarfile.TarError, KeyError, ValueError) as exc:
        errors.append(str(exc))

    return not errors, errors, summary
