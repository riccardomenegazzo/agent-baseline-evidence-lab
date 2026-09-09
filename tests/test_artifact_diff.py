import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from agent_baseline_lab.artifact_diff import (
    create_artifact_diff,
    verify_artifact_diff,
)
from agent_baseline_lab.evidence import sha256_file
from agent_baseline_lab.trusted_artifact import SPDX_PREDICATE


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write_oci(
    path: Path,
    *,
    layer_content: bytes = b"layer-a",
    material_digest: str = "a" * 64,
    provenance_nonce: str = "same",
    reverse_members: bool = False,
    tar_mtime: int = 0,
) -> None:
    layer_digest = _digest(layer_content)
    config = _json_bytes(
        {
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
        }
    )
    config_digest = _digest(config)
    runnable = _json_bytes(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": layer_digest,
                    "size": len(layer_content),
                }
            ],
        }
    )
    runnable_digest = _digest(runnable)
    subject_hash = runnable_digest.split(":", 1)[1]

    sbom = _json_bytes(
        {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": SPDX_PREDICATE,
            "subject": [{"name": "sample", "digest": {"sha256": subject_hash}}],
            "predicate": {"spdxVersion": "SPDX-2.3"},
        }
    )
    provenance = _json_bytes(
        {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "subject": [{"name": "sample", "digest": {"sha256": subject_hash}}],
            "predicate": {
                "materials": [
                    {
                        "uri": "pkg:docker/python@sha256:base",
                        "digest": {"sha256": material_digest},
                    }
                ],
                "metadata": {"buildInvocationId": provenance_nonce},
            },
        }
    )
    sbom_digest = _digest(sbom)
    provenance_digest = _digest(provenance)
    empty_config = b"{}"
    empty_config_digest = _digest(empty_config)

    attestation = _json_bytes(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": empty_config_digest,
                "size": len(empty_config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.in-toto+json",
                    "digest": sbom_digest,
                    "size": len(sbom),
                    "annotations": {"in-toto.io/predicate-type": SPDX_PREDICATE},
                },
                {
                    "mediaType": "application/vnd.in-toto+json",
                    "digest": provenance_digest,
                    "size": len(provenance),
                    "annotations": {
                        "in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2"
                    },
                },
            ],
        }
    )
    attestation_digest = _digest(attestation)
    index = _json_bytes(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": runnable_digest,
                    "size": len(runnable),
                    "platform": {"architecture": "amd64", "os": "linux"},
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": attestation_digest,
                    "size": len(attestation),
                    "annotations": {
                        "vnd.docker.reference.type": "attestation-manifest",
                        "vnd.docker.reference.digest": runnable_digest,
                    },
                    "platform": {"architecture": "unknown", "os": "unknown"},
                },
            ],
        }
    )

    blobs = {
        config_digest: config,
        layer_digest: layer_content,
        runnable_digest: runnable,
        empty_config_digest: empty_config,
        sbom_digest: sbom,
        provenance_digest: provenance,
        attestation_digest: attestation,
    }
    members = [
        ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
        ("index.json", index),
        *[
            (f"blobs/sha256/{digest.split(':', 1)[1]}", data)
            for digest, data in sorted(blobs.items())
        ],
    ]
    if reverse_members:
        members.reverse()

    with tarfile.open(path, "w") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = tar_mtime
            tf.addfile(info, io.BytesIO(data))


def _report(path: Path, archive: Path, *, base: str = "python:3.13-slim") -> Path:
    payload = {
        "schema_version": 1,
        "overall_status": "VERIFIED",
        "oci_archive": archive.name,
        "oci_archive_sha256": sha256_file(archive),
        "scout_status": "PASS",
        "checks": [
            {
                "id": "base-image-identity",
                "status": "PASS",
                "summary": "base observed",
                "evidence": {
                    "external_bases": [base],
                    "digest_pinned": [base] if "@sha256:" in base else [],
                    "tag_only": [] if "@sha256:" in base else [base],
                },
            }
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def test_repacked_archive_is_not_mislabeled_as_artifact_change(tmp_path: Path):
    before_archive = tmp_path / "before.oci.tar"
    after_archive = tmp_path / "after.oci.tar"
    _write_oci(before_archive, reverse_members=False, tar_mtime=0)
    _write_oci(after_archive, reverse_members=True, tar_mtime=123)
    before = _report(tmp_path / "before.json", before_archive)
    after = _report(tmp_path / "after.json", after_archive)

    result = create_artifact_diff(
        before,
        after,
        root_path=tmp_path,
        output="diff.json",
        html_output="diff.html",
    )

    assert result.classification == "REPACKAGED_EQUIVALENT"
    assert result.before.archive_sha256 != result.after.archive_sha256
    assert result.before.runnable_graph_sha256 == result.after.runnable_graph_sha256
    assert (
        result.before.supply_chain_fingerprint_sha256
        == result.after.supply_chain_fingerprint_sha256
    )
    assert result.changes["layers"] == {"added": [], "removed": []}
    assert (tmp_path / "diff.html").is_file()


def test_layer_change_is_reported_as_artifact_change(tmp_path: Path):
    before_archive = tmp_path / "before.oci.tar"
    after_archive = tmp_path / "after.oci.tar"
    _write_oci(before_archive, layer_content=b"layer-a")
    _write_oci(after_archive, layer_content=b"layer-b")
    before = _report(tmp_path / "before.json", before_archive)
    after = _report(tmp_path / "after.json", after_archive)

    result = create_artifact_diff(before, after, root_path=tmp_path, output="diff.json")

    assert result.classification == "ARTIFACT_CHANGED"
    assert result.changes["runnable_graph_changed"] is True
    assert len(result.changes["layers"]["added"]) == 1
    assert len(result.changes["layers"]["removed"]) == 1


def test_provenance_material_change_is_visible_without_claiming_runnable_change(tmp_path: Path):
    before_archive = tmp_path / "before.oci.tar"
    after_archive = tmp_path / "after.oci.tar"
    _write_oci(before_archive, material_digest="a" * 64)
    _write_oci(after_archive, material_digest="b" * 64)
    before = _report(tmp_path / "before.json", before_archive)
    after = _report(tmp_path / "after.json", after_archive)

    result = create_artifact_diff(before, after, root_path=tmp_path, output="diff.json")

    assert result.classification == "BUILD_EVIDENCE_CHANGED"
    assert result.changes["runnable_graph_changed"] is False
    assert result.changes["supply_chain_fingerprint_changed"] is True
    changes = result.changes["provenance_materials"]["digest_changes"]
    assert len(changes) == 1
    assert changes[0]["uri"] == "pkg:docker/python@sha256:base"
    assert changes[0]["before"] == [{"sha256": "a" * 64}]
    assert changes[0]["after"] == [{"sha256": "b" * 64}]


def test_attestation_nonce_does_not_change_selected_supply_chain_fingerprint(tmp_path: Path):
    before_archive = tmp_path / "before.oci.tar"
    after_archive = tmp_path / "after.oci.tar"
    _write_oci(before_archive, provenance_nonce="build-1")
    _write_oci(after_archive, provenance_nonce="build-2")
    before = _report(tmp_path / "before.json", before_archive)
    after = _report(tmp_path / "after.json", after_archive)

    result = create_artifact_diff(before, after, root_path=tmp_path, output="diff.json")

    assert result.classification == "REPACKAGED_EQUIVALENT"
    assert result.changes["runnable_graph_changed"] is False
    assert result.changes["supply_chain_fingerprint_changed"] is False
    assert result.changes["attestation_statements"]["added"]
    assert result.changes["attestation_statements"]["removed"]


def test_verifier_detects_diff_tampering(tmp_path: Path):
    archive = tmp_path / "image.oci.tar"
    _write_oci(archive)
    before = _report(tmp_path / "before.json", archive)
    after = _report(tmp_path / "after.json", archive)
    diff = tmp_path / "diff.json"
    create_artifact_diff(before, after, root_path=tmp_path, output=diff)

    payload = json.loads(diff.read_text(encoding="utf-8"))
    payload["classification"] = "ARTIFACT_CHANGED"
    diff.write_text(json.dumps(payload), encoding="utf-8")

    ok, errors, recomputed = verify_artifact_diff(
        diff,
        before,
        after,
        root_path=tmp_path,
    )

    assert ok is False
    assert recomputed.classification == "IDENTICAL"
    assert "artifact diff mismatch: classification" in errors


def test_artifact_diff_fails_closed_on_report_archive_digest_mismatch(tmp_path: Path):
    archive = tmp_path / "image.oci.tar"
    _write_oci(archive)
    before = _report(tmp_path / "before.json", archive)
    after = _report(tmp_path / "after.json", archive)
    payload = json.loads(after.read_text(encoding="utf-8"))
    payload["oci_archive_sha256"] = "0" * 64
    after.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="OCI archive digest does not match"):
        create_artifact_diff(before, after, root_path=tmp_path, output="diff.json")
