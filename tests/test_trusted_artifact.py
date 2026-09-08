import hashlib
import io
import json
import tarfile
from pathlib import Path

from agent_baseline_lab.trusted_artifact import (
    SPDX_PREDICATE,
    inspect_dockerfile,
    run_trusted_artifact,
    verify_oci_attestations,
)


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write_oci_archive(path: Path, *, include_provenance: bool = True, bind_subject: bool = True) -> None:
    runnable = _json_bytes(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + "1" * 64, "size": 2},
            "layers": [],
        }
    )
    runnable_digest = _digest(runnable)
    subject_hash = runnable_digest.split(":", 1)[1] if bind_subject else "f" * 64

    statements = [
        _json_bytes(
            {
                "_type": "https://in-toto.io/Statement/v0.1",
                "predicateType": SPDX_PREDICATE,
                "subject": [{"name": "sample", "digest": {"sha256": subject_hash}}],
                "predicate": {"spdxVersion": "SPDX-2.3"},
            }
        )
    ]
    if include_provenance:
        statements.append(
            _json_bytes(
                {
                    "_type": "https://in-toto.io/Statement/v0.1",
                    "predicateType": "https://slsa.dev/provenance/v0.2",
                    "subject": [{"name": "sample", "digest": {"sha256": subject_hash}}],
                    "predicate": {"buildType": "https://mobyproject.org/buildkit@v1"},
                }
            )
        )

    layers = []
    blobs: dict[str, bytes] = {runnable_digest: runnable}
    for statement in statements:
        digest = _digest(statement)
        blobs[digest] = statement
        predicate = json.loads(statement)["predicateType"]
        layers.append(
            {
                "mediaType": "application/vnd.in-toto+json",
                "digest": digest,
                "size": len(statement),
                "annotations": {"in-toto.io/predicate-type": predicate},
            }
        )

    attestation_manifest = _json_bytes(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": layers,
            "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:" + "0" * 64, "size": 2},
        }
    )
    attestation_digest = _digest(attestation_manifest)
    blobs[attestation_digest] = attestation_manifest

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
                    "size": len(attestation_manifest),
                    "annotations": {
                        "vnd.docker.reference.type": "attestation-manifest",
                        "vnd.docker.reference.digest": runnable_digest,
                    },
                    "platform": {"architecture": "unknown", "os": "unknown"},
                },
            ],
        }
    )

    with tarfile.open(path, "w") as tf:
        for name, data in {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": index,
            **{f"blobs/sha256/{digest.split(':', 1)[1]}": data for digest, data in blobs.items()},
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))


def test_verify_oci_attestations_requires_sbom_provenance_and_subject_binding(tmp_path: Path):
    archive = tmp_path / "image.oci.tar"
    _write_oci_archive(archive)

    ok, errors, summary = verify_oci_attestations(archive)

    assert ok is True
    assert errors == []
    assert summary["sbom_present"] is True
    assert summary["provenance_present"] is True
    assert summary["subject_bindings_valid"] is True


def test_verify_oci_attestations_rejects_missing_provenance(tmp_path: Path):
    archive = tmp_path / "image.oci.tar"
    _write_oci_archive(archive, include_provenance=False)

    ok, errors, summary = verify_oci_attestations(archive)

    assert ok is False
    assert summary["sbom_present"] is True
    assert summary["provenance_present"] is False
    assert "SLSA provenance attestation is missing" in errors


def test_verify_oci_attestations_rejects_subject_mismatch(tmp_path: Path):
    archive = tmp_path / "image.oci.tar"
    _write_oci_archive(archive, bind_subject=False)

    ok, errors, summary = verify_oci_attestations(archive)

    assert ok is False
    assert summary["subject_bindings_valid"] is False
    assert any("subject-bound" in error for error in errors)


def test_verify_oci_attestations_rejects_blob_tampering(tmp_path: Path):
    archive = tmp_path / "image.oci.tar"
    _write_oci_archive(archive)
    tampered = tmp_path / "tampered.oci.tar"

    with tarfile.open(archive, "r") as source, tarfile.open(tampered, "w") as target:
        changed = False
        for member in source.getmembers():
            stream = source.extractfile(member) if member.isfile() else None
            data = stream.read() if stream is not None else b""
            if member.name.startswith("blobs/sha256/") and not changed:
                data += b"tamper"
                member.size = len(data)
                changed = True
            target.addfile(member, io.BytesIO(data) if member.isfile() else None)

    ok, errors, _ = verify_oci_attestations(tampered)

    assert ok is False
    assert any("digest mismatch" in error for error in errors)


def test_dockerfile_contract_distinguishes_non_root_and_mutable_base(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.13-slim\nUSER app\nHEALTHCHECK CMD true\n", encoding="utf-8")

    checks = {item.id: item for item in inspect_dockerfile(dockerfile)}

    assert checks["default-non-root-user"].status == "PASS"
    assert checks["base-image-reproducibility"].status == "FINDING"
    assert checks["runtime-healthcheck"].status == "PASS"


def test_dockerfile_contract_rejects_implicit_root(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.13-slim\nCMD [\"python\"]\n", encoding="utf-8")

    checks = {item.id: item for item in inspect_dockerfile(dockerfile)}

    assert checks["default-non-root-user"].status == "FAIL"


def test_trusted_artifact_dry_run_never_claims_live_attestations(tmp_path: Path):
    context = tmp_path / "app"
    context.mkdir()
    (context / "Dockerfile").write_text(
        "FROM python:3.13-slim\nUSER app\nHEALTHCHECK CMD true\n",
        encoding="utf-8",
    )

    report = run_trusted_artifact(
        context,
        output_root=tmp_path,
        output_dir="reports/trusted-artifact",
        dry_run=True,
        scout_mode="off",
    )

    checks = {item.id: item for item in report.checks}
    assert report.build_attempted is False
    assert report.build_succeeded is False
    assert report.overall_status == "NOT_RUN"
    assert checks["buildkit-attestations"].status == "NOT_RUN"
    assert report.oci_archive_sha256 == ""
