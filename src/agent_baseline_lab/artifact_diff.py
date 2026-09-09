from __future__ import annotations

import argparse
import hashlib
import html
import json
import tarfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .evidence import sha256_file
from .oci_integrity import verify_oci_layout_integrity
from .trusted_artifact import ATTESTATION_MANIFEST, SLSA_PREFIX, verify_oci_attestations

SCHEMA_VERSION = 1
MAX_JSON_BLOB_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class ArtifactSnapshot:
    report_sha256: str
    archive_sha256: str
    runnable_graph_sha256: str
    supply_chain_fingerprint_sha256: str
    runnable_images: list[dict[str, Any]]
    predicate_types: list[str]
    provenance_materials: list[dict[str, Any]]
    attestation_statement_digests: list[str]
    declared_base_images: dict[str, list[str]]
    scout_status: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ArtifactDiff:
    schema_version: int
    generated_at: str
    classification: str
    before: ArtifactSnapshot
    after: ArtifactSnapshot
    changes: dict[str, Any]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["before"] = self.before.to_dict()
        payload["after"] = self.after.to_dict()
        return payload


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value))


def _blob_name(digest: str) -> str:
    algorithm, separator, value = digest.partition(":")
    if separator != ":" or algorithm != "sha256" or len(value) != 64:
        raise ValueError(f"unsupported OCI digest: {digest}")
    return f"blobs/sha256/{value}"


def _read_member(tf: tarfile.TarFile, name: str) -> bytes:
    try:
        member = tf.getmember(name)
    except KeyError as exc:
        raise ValueError(f"missing OCI member: {name}") from exc
    if not member.isfile():
        raise ValueError(f"OCI member is not a regular file: {name}")
    if member.size > MAX_JSON_BLOB_BYTES:
        raise ValueError(f"OCI JSON member exceeds {MAX_JSON_BLOB_BYTES} bytes: {name}")
    stream = tf.extractfile(member)
    if stream is None:
        raise ValueError(f"OCI member cannot be read: {name}")
    return stream.read()


def _read_json_member(tf: tarfile.TarFile, name: str) -> dict[str, Any]:
    data = _read_member(tf, name)
    try:
        payload = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid OCI JSON member {name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"OCI JSON member is not an object: {name}")
    return payload


def _read_json_blob(tf: tarfile.TarFile, digest: str) -> dict[str, Any]:
    data = _read_member(tf, _blob_name(digest))
    expected = digest.split(":", 1)[1]
    if _sha256_bytes(data) != expected:
        raise ValueError(f"OCI blob digest mismatch for {digest}")
    try:
        payload = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError(f"OCI blob is not JSON: {digest}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"OCI blob is not a JSON object: {digest}")
    return payload


def _load_json(path: Path, *, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"{label} does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid {label} JSON {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return payload


def _resolve(root: Path, value: str, *, label: str) -> Path:
    if not value or value.startswith("<external>/"):
        raise ValueError(f"{label} does not contain a locally resolvable path")
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _check_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    checks = report.get("checks", [])
    if not isinstance(checks, list):
        raise ValueError("trusted artifact checks must be an array")
    mapped: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(checks, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"trusted artifact check {index} is malformed")
        check_id = str(item.get("id", "")).strip()
        if not check_id:
            raise ValueError(f"trusted artifact check {index} has no id")
        if check_id in mapped:
            raise ValueError(f"trusted artifact contains duplicate check id: {check_id}")
        mapped[check_id] = item
    return mapped


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({str(item) for item in value if isinstance(item, str) and item})


def _declared_base_images(checks: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    identity = checks.get("base-image-identity", {})
    evidence = identity.get("evidence", {}) if isinstance(identity, dict) else {}
    if not isinstance(evidence, dict):
        evidence = {}
    return {
        "external_bases": _string_list(evidence.get("external_bases")),
        "digest_pinned": _string_list(evidence.get("digest_pinned")),
        "tag_only": _string_list(evidence.get("tag_only")),
    }


def _normalize_digest_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key): str(digest)
        for key, digest in sorted(value.items(), key=lambda item: str(item[0]))
        if isinstance(digest, str) and digest
    }


def _normalize_material(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    uri = str(item.get("uri", ""))
    digest = _normalize_digest_map(item.get("digest"))
    if not uri and not digest:
        return None
    return {"uri": uri, "digest": digest}


def _provenance_materials(predicate_type: str, predicate: Any) -> list[dict[str, Any]]:
    if not predicate_type.startswith(SLSA_PREFIX) or not isinstance(predicate, dict):
        return []
    candidates: list[Any] = []
    materials = predicate.get("materials")
    if isinstance(materials, list):
        candidates.extend(materials)
    build_definition = predicate.get("buildDefinition")
    if isinstance(build_definition, dict):
        resolved = build_definition.get("resolvedDependencies")
        if isinstance(resolved, list):
            candidates.extend(resolved)

    normalized: dict[str, dict[str, Any]] = {}
    for item in candidates:
        material = _normalize_material(item)
        if material is None:
            continue
        normalized[_canonical_json(material).decode("utf-8")] = material
    return [normalized[key] for key in sorted(normalized)]


def _platform_label(value: Any) -> str:
    if not isinstance(value, dict):
        return "unknown/unknown"
    os_name = str(value.get("os", "unknown"))
    architecture = str(value.get("architecture", "unknown"))
    variant = str(value.get("variant", ""))
    label = f"{os_name}/{architecture}"
    return f"{label}/{variant}" if variant else label


def _oci_snapshot(archive: Path) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]], list[str]]:
    runnable_images: list[dict[str, Any]] = []
    predicates: set[str] = set()
    materials: dict[str, dict[str, Any]] = {}
    statement_digests: set[str] = set()

    with tarfile.open(archive, "r:*") as tf:
        index = _read_json_member(tf, "index.json")
        descriptors = index.get("manifests", [])
        if not isinstance(descriptors, list):
            raise ValueError("OCI index manifests must be an array")

        for descriptor in descriptors:
            if not isinstance(descriptor, dict):
                raise ValueError("OCI index contains a malformed descriptor")
            annotations = descriptor.get("annotations", {})
            annotations = annotations if isinstance(annotations, dict) else {}
            digest = str(descriptor.get("digest", ""))
            if annotations.get("vnd.docker.reference.type") == ATTESTATION_MANIFEST:
                attestation = _read_json_blob(tf, digest)
                layers = attestation.get("layers", [])
                if not isinstance(layers, list):
                    raise ValueError(f"attestation manifest layers must be an array: {digest}")
                for layer in layers:
                    if not isinstance(layer, dict):
                        continue
                    if layer.get("mediaType") != "application/vnd.in-toto+json":
                        continue
                    statement_digest = str(layer.get("digest", ""))
                    statement = _read_json_blob(tf, statement_digest)
                    predicate_type = str(statement.get("predicateType", ""))
                    if predicate_type:
                        predicates.add(predicate_type)
                    statement_digests.add(statement_digest)
                    for material in _provenance_materials(
                        predicate_type,
                        statement.get("predicate"),
                    ):
                        materials[_canonical_json(material).decode("utf-8")] = material
                continue

            manifest = _read_json_blob(tf, digest)
            config = manifest.get("config", {})
            if not isinstance(config, dict):
                raise ValueError(f"OCI runnable manifest has invalid config descriptor: {digest}")
            layers = manifest.get("layers", [])
            if not isinstance(layers, list):
                raise ValueError(f"OCI runnable manifest layers must be an array: {digest}")
            layer_digests = [
                str(layer.get("digest", ""))
                for layer in layers
                if isinstance(layer, dict) and layer.get("digest")
            ]
            runnable_images.append(
                {
                    "platform": _platform_label(descriptor.get("platform")),
                    "manifest_digest": digest,
                    "config_digest": str(config.get("digest", "")),
                    "layer_digests": layer_digests,
                }
            )

    runnable_images.sort(key=lambda item: (item["platform"], item["manifest_digest"]))
    return (
        runnable_images,
        sorted(predicates),
        [materials[key] for key in sorted(materials)],
        sorted(statement_digests),
    )


def _verified_snapshot(report_path: Path, root: Path) -> ArtifactSnapshot:
    report = _load_json(report_path, label="trusted artifact report")
    if report.get("overall_status") != "VERIFIED":
        raise ValueError("artifact diff requires trusted artifact reports with overall_status VERIFIED")

    archive = _resolve(root, str(report.get("oci_archive", "")), label="trusted artifact report")
    expected_archive_sha = str(report.get("oci_archive_sha256", ""))
    if not archive.is_file() or not expected_archive_sha:
        raise ValueError("trusted artifact report does not identify an existing OCI archive")
    observed_archive_sha = sha256_file(archive)
    if observed_archive_sha != expected_archive_sha:
        raise ValueError("OCI archive digest does not match the trusted artifact report")

    graph_ok, graph_errors, _ = verify_oci_layout_integrity(archive)
    if not graph_ok:
        raise ValueError("OCI graph verification failed: " + "; ".join(graph_errors))
    attestation_ok, attestation_errors, attestation_summary = verify_oci_attestations(archive)
    if not attestation_ok:
        raise ValueError(
            "OCI attestation verification failed: " + "; ".join(attestation_errors)
        )

    runnable, predicates, materials, statement_digests = _oci_snapshot(archive)
    if not runnable:
        raise ValueError("verified OCI archive contains no runnable image")
    runnable_fingerprint = _canonical_sha256(runnable)
    supply_chain_fingerprint = _canonical_sha256(
        {
            "predicate_types": predicates,
            "provenance_materials": materials,
            "sbom_present": bool(attestation_summary.get("sbom_present")),
            "provenance_present": bool(attestation_summary.get("provenance_present")),
            "subject_bindings_valid": bool(
                attestation_summary.get("subject_bindings_valid")
            ),
        }
    )

    return ArtifactSnapshot(
        report_sha256=sha256_file(report_path),
        archive_sha256=observed_archive_sha,
        runnable_graph_sha256=runnable_fingerprint,
        supply_chain_fingerprint_sha256=supply_chain_fingerprint,
        runnable_images=runnable,
        predicate_types=predicates,
        provenance_materials=materials,
        attestation_statement_digests=statement_digests,
        declared_base_images=_declared_base_images(_check_map(report)),
        scout_status=str(report.get("scout_status", "NOT_RUN")),
    )


def _flatten(snapshot: ArtifactSnapshot, key: str) -> list[str]:
    values: set[str] = set()
    for image in snapshot.runnable_images:
        if key == "layer_digests":
            values.update(str(value) for value in image.get(key, []) if value)
        else:
            value = str(image.get(key, ""))
            if value:
                values.add(value)
    return sorted(values)


def _set_changes(before: list[str], after: list[str]) -> dict[str, list[str]]:
    before_set = set(before)
    after_set = set(after)
    return {
        "added": sorted(after_set - before_set),
        "removed": sorted(before_set - after_set),
    }


def _material_map(materials: list[dict[str, Any]]) -> dict[str, list[dict[str, str]]]:
    mapped: dict[str, list[dict[str, str]]] = {}
    for item in materials:
        uri = str(item.get("uri", ""))
        digest = _normalize_digest_map(item.get("digest"))
        mapped.setdefault(uri, []).append(digest)
    for uri in mapped:
        mapped[uri] = sorted(mapped[uri], key=lambda value: _canonical_json(value))
    return mapped


def _material_changes(
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> dict[str, Any]:
    before_rows = {_canonical_json(item).decode("utf-8"): item for item in before}
    after_rows = {_canonical_json(item).decode("utf-8"): item for item in after}
    before_map = _material_map(before)
    after_map = _material_map(after)
    digest_changes: list[dict[str, Any]] = []
    for uri in sorted(set(before_map) & set(after_map)):
        if before_map[uri] != after_map[uri]:
            digest_changes.append(
                {
                    "uri": uri,
                    "before": before_map[uri],
                    "after": after_map[uri],
                }
            )
    return {
        "added": [after_rows[key] for key in sorted(set(after_rows) - set(before_rows))],
        "removed": [before_rows[key] for key in sorted(set(before_rows) - set(after_rows))],
        "digest_changes": digest_changes,
    }


def _base_changes(before: ArtifactSnapshot, after: ArtifactSnapshot) -> dict[str, Any]:
    return {
        key: _set_changes(before.declared_base_images.get(key, []), after.declared_base_images.get(key, []))
        for key in ("external_bases", "digest_pinned", "tag_only")
    }


def _changes(before: ArtifactSnapshot, after: ArtifactSnapshot) -> dict[str, Any]:
    return {
        "archive_bytes_changed": before.archive_sha256 != after.archive_sha256,
        "runnable_graph_changed": before.runnable_graph_sha256 != after.runnable_graph_sha256,
        "supply_chain_fingerprint_changed": (
            before.supply_chain_fingerprint_sha256
            != after.supply_chain_fingerprint_sha256
        ),
        "scout_status": {"before": before.scout_status, "after": after.scout_status},
        "runnable_manifests": _set_changes(
            _flatten(before, "manifest_digest"),
            _flatten(after, "manifest_digest"),
        ),
        "configs": _set_changes(
            _flatten(before, "config_digest"),
            _flatten(after, "config_digest"),
        ),
        "layers": _set_changes(
            _flatten(before, "layer_digests"),
            _flatten(after, "layer_digests"),
        ),
        "predicate_types": _set_changes(before.predicate_types, after.predicate_types),
        "attestation_statements": _set_changes(
            before.attestation_statement_digests,
            after.attestation_statement_digests,
        ),
        "provenance_materials": _material_changes(
            before.provenance_materials,
            after.provenance_materials,
        ),
        "declared_base_images": _base_changes(before, after),
    }


def _has_base_change(changes: dict[str, Any]) -> bool:
    base = changes.get("declared_base_images", {})
    if not isinstance(base, dict):
        return False
    for value in base.values():
        if isinstance(value, dict) and (value.get("added") or value.get("removed")):
            return True
    return False


def _classification(before: ArtifactSnapshot, after: ArtifactSnapshot, changes: dict[str, Any]) -> str:
    if before.runnable_graph_sha256 != after.runnable_graph_sha256:
        return "ARTIFACT_CHANGED"
    if (
        before.supply_chain_fingerprint_sha256 != after.supply_chain_fingerprint_sha256
        or _has_base_change(changes)
        or before.scout_status != after.scout_status
    ):
        return "BUILD_EVIDENCE_CHANGED"
    if before.archive_sha256 != after.archive_sha256:
        return "REPACKAGED_EQUIVALENT"
    return "IDENTICAL"


def build_artifact_diff(
    before: ArtifactSnapshot,
    after: ArtifactSnapshot,
    *,
    generated_at: str | None = None,
) -> ArtifactDiff:
    changes = _changes(before, after)
    classification = _classification(before, after, changes)
    return ArtifactDiff(
        schema_version=SCHEMA_VERSION,
        generated_at=generated_at or _utc_now(),
        classification=classification,
        before=before,
        after=after,
        changes=changes,
        claims_boundary=(
            "This comparison distinguishes byte identity of the OCI tar archives from identity of the "
            "verified runnable OCI graph and selected supply-chain evidence. REPACKAGED_EQUIVALENT means "
            "the modeled runnable graph, provenance-material/predicate fingerprint, declared base-image "
            "evidence and Scout status are unchanged despite different archive bytes. The comparison does "
            "not prove behavioral equivalence, explain causality, establish vulnerability absence, or infer "
            "that a provenance material is a base image unless the source evidence says so."
        ),
    )


def create_artifact_diff(
    before_report: str | Path,
    after_report: str | Path,
    *,
    root_path: str | Path = ".",
    output: str | Path = "reports/oci-artifact-diff.json",
    html_output: str | Path | None = "reports/oci-artifact-diff.html",
) -> ArtifactDiff:
    root = Path(root_path).resolve()
    before_path = Path(before_report)
    after_path = Path(after_report)
    if not before_path.is_absolute():
        before_path = root / before_path
    if not after_path.is_absolute():
        after_path = root / after_path
    result = build_artifact_diff(
        _verified_snapshot(before_path, root),
        _verified_snapshot(after_path, root),
    )
    destination = Path(output)
    if not destination.is_absolute():
        destination = root / destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if html_output is not None:
        html_path = Path(html_output)
        if not html_path.is_absolute():
            html_path = root / html_path
        _write_html(result, html_path)
    return result


def verify_artifact_diff(
    diff_path: str | Path,
    before_report: str | Path,
    after_report: str | Path,
    *,
    root_path: str | Path = ".",
) -> tuple[bool, list[str], ArtifactDiff]:
    root = Path(root_path).resolve()
    diff_file = Path(diff_path)
    before_path = Path(before_report)
    after_path = Path(after_report)
    for name, path in (("diff", diff_file), ("before", before_path), ("after", after_path)):
        if not path.is_absolute():
            path = root / path
        if name == "diff":
            diff_file = path
        elif name == "before":
            before_path = path
        else:
            after_path = path
    existing = _load_json(diff_file, label="artifact diff")
    if existing.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported artifact diff schema_version")
    generated_at = str(existing.get("generated_at", "")) or _utc_now()
    recomputed = build_artifact_diff(
        _verified_snapshot(before_path, root),
        _verified_snapshot(after_path, root),
        generated_at=generated_at,
    )
    expected = recomputed.to_dict()
    errors = [
        f"artifact diff mismatch: {field}"
        for field in (
            "schema_version",
            "generated_at",
            "classification",
            "before",
            "after",
            "changes",
            "claims_boundary",
        )
        if existing.get(field) != expected.get(field)
    ]
    return not errors, errors, recomputed


def _render_list(values: list[Any], empty: str) -> str:
    if not values:
        return f"<li>{html.escape(empty)}</li>"
    return "".join(
        f"<li><code>{html.escape(json.dumps(value, sort_keys=True) if isinstance(value, dict) else str(value))}</code></li>"
        for value in values
    )


def _write_html(result: ArtifactDiff, path: Path) -> None:
    layer_changes = result.changes["layers"]
    material_changes = result.changes["provenance_materials"]
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OCI Artifact Diff</title><style>
body{{margin:0;background:#f7f9fc;color:#101828;font:15px/1.55 system-ui,sans-serif}}.wrap{{max-width:1050px;margin:auto;padding:48px 24px 80px}}header{{background:linear-gradient(135deg,#0b1f3a,#164d8b);color:#fff;padding:34px;border-radius:20px}}h1{{margin:6px 0 10px;font-size:38px}}.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:20px 0}}.card,section{{background:#fff;border:1px solid #e4e7ec;border-radius:14px;padding:18px}}.card span{{display:block;color:#667085;font-size:12px}}.card strong{{overflow-wrap:anywhere}}section{{margin:12px 0}}code{{font-size:12px;overflow-wrap:anywhere}}.notice{{background:#fff8e8;border:1px solid #f5d477;border-radius:12px;padding:14px 16px}}@media(max-width:760px){{.grid{{grid-template-columns:1fr}}h1{{font-size:30px}}}}</style></head><body><div class="wrap"><header><div>AGENT BASELINE EVIDENCE LAB</div><h1>Verified OCI Artifact Diff</h1><p>Byte-level identity is separated from the verified runnable OCI graph and selected supply-chain evidence.</p></header><div class="grid"><div class="card"><span>Classification</span><strong>{html.escape(result.classification)}</strong></div><div class="card"><span>Runnable graph changed</span><strong>{result.changes['runnable_graph_changed']}</strong></div><div class="card"><span>Supply-chain evidence changed</span><strong>{result.changes['supply_chain_fingerprint_changed']}</strong></div></div><section><h2>Layers added</h2><ul>{_render_list(layer_changes['added'], 'No layers added.')}</ul><h2>Layers removed</h2><ul>{_render_list(layer_changes['removed'], 'No layers removed.')}</ul></section><section><h2>Provenance materials added</h2><ul>{_render_list(material_changes['added'], 'No materials added.')}</ul><h2>Provenance materials removed</h2><ul>{_render_list(material_changes['removed'], 'No materials removed.')}</ul><h2>Material digest changes</h2><ul>{_render_list(material_changes['digest_changes'], 'No same-URI material digest changes.')}</ul></section><div class="notice"><strong>Claims boundary:</strong> {html.escape(result.claims_boundary)}</div></div></body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create or verify deterministic evidence about changes between two trusted OCI artifacts"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("before")
    create.add_argument("after")
    create.add_argument("--root", default=".")
    create.add_argument("--output", default="reports/oci-artifact-diff.json")
    create.add_argument("--html", default="reports/oci-artifact-diff.html")
    verify = sub.add_parser("verify")
    verify.add_argument("diff")
    verify.add_argument("before")
    verify.add_argument("after")
    verify.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            result = create_artifact_diff(
                args.before,
                args.after,
                root_path=args.root,
                output=args.output,
                html_output=args.html,
            )
            print("VERIFIED OCI ARTIFACT DIFF")
            print(f"  classification: {result.classification}")
            print(f"  graph changed:  {result.changes['runnable_graph_changed']}")
            print(
                "  supply changed: "
                f"{result.changes['supply_chain_fingerprint_changed']}"
            )
            return 0
        ok, errors, result = verify_artifact_diff(
            args.diff,
            args.before,
            args.after,
            root_path=args.root,
        )
        print("OCI ARTIFACT DIFF VERIFICATION")
        print(f"  classification: {result.classification}")
        print(f"  status: {'VERIFIED' if ok else 'FAILED'}")
        for error in errors:
            print(f"ERROR: {error}")
        return 0 if ok else 1
    except (OSError, ValueError, KeyError, tarfile.TarError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
