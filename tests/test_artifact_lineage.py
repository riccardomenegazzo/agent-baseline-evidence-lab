import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from agent_baseline_lab.artifact_lineage import (
    create_lineage_statement,
    verify_lineage_statement,
)
from agent_baseline_lab.evidence import EvidenceStore, sha256_file


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _desc(data: bytes, media: str, **extra) -> dict:
    return {"mediaType": media, "digest": _digest(data), "size": len(data), **extra}


def _workspace_digest(root: Path) -> str:
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and ".git" not in path.parts and "__pycache__" not in path.parts:
            entries.append((path.relative_to(root).as_posix(), sha256_file(path)))
    digest = hashlib.sha256()
    for rel, file_hash in entries:
        digest.update(rel.encode())
        digest.update(b"\0")
        digest.update(file_hash.encode())
        digest.update(b"\n")
    return digest.hexdigest()


def _write_verified_oci(path: Path) -> None:
    config = _json({"architecture": "amd64", "os": "linux", "config": {"User": "app"}})
    layer = b"application-layer\n"
    runnable = _json(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": _desc(config, "application/vnd.oci.image.config.v1+json"),
            "layers": [_desc(layer, "application/vnd.oci.image.layer.v1.tar")],
        }
    )
    runnable_desc = _desc(runnable, "application/vnd.oci.image.manifest.v1+json")
    runnable_hash = runnable_desc["digest"].split(":", 1)[1]

    sbom = _json(
        {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://spdx.dev/Document",
            "subject": [{"name": "image", "digest": {"sha256": runnable_hash}}],
            "predicate": {"spdxVersion": "SPDX-2.3"},
        }
    )
    provenance = _json(
        {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "subject": [{"name": "image", "digest": {"sha256": runnable_hash}}],
            "predicate": {"buildType": "https://mobyproject.org/buildkit@v1"},
        }
    )
    empty_config = b"{}"
    sbom_desc = _desc(
        sbom,
        "application/vnd.in-toto+json",
        annotations={"in-toto.io/predicate-type": "https://spdx.dev/Document"},
    )
    provenance_desc = _desc(
        provenance,
        "application/vnd.in-toto+json",
        annotations={"in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2"},
    )
    attestation = _json(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": _desc(empty_config, "application/vnd.oci.empty.v1+json"),
            "layers": [sbom_desc, provenance_desc],
        }
    )
    attestation_desc = _desc(
        attestation,
        "application/vnd.oci.image.manifest.v1+json",
        annotations={
            "vnd.docker.reference.type": "attestation-manifest",
            "vnd.docker.reference.digest": runnable_desc["digest"],
        },
        platform={"architecture": "unknown", "os": "unknown"},
    )
    index = _json(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [runnable_desc, attestation_desc],
        }
    )
    blobs = {
        runnable_desc["digest"]: runnable,
        _digest(config): config,
        _digest(layer): layer,
        attestation_desc["digest"]: attestation,
        _digest(empty_config): empty_config,
        sbom_desc["digest"]: sbom,
        provenance_desc["digest"]: provenance,
    }
    with tarfile.open(path, "w") as tf:
        members = {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": index,
            **{f"blobs/sha256/{digest.split(':', 1)[1]}": data for digest, data in blobs.items()},
        }
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    workspace = tmp_path / ".abl-workspaces" / "agent-test" / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "app.py").write_text("print('agent output')\n", encoding="utf-8")
    (workspace / "Dockerfile").write_text("FROM python:3.13-slim\nUSER app\n", encoding="utf-8")
    workspace_hash = _workspace_digest(workspace)

    run_dir = tmp_path / "agent-runs" / "agent-test"
    store = EvidenceStore(run_dir)
    session = {
        "schema_version": 1,
        "session_id": "agent-test",
        "agent": "codex",
        "sandbox_name": "abl-agent-test",
        "workspace": ".abl-workspaces/agent-test/workspace",
        "task": {"sha256": "a" * 64},
        "execution": {"attempted": True, "returncode": 0},
        "workspace_after": {"root_sha256": workspace_hash},
    }
    store.write_json("session.json", session)
    store.finalize_manifest()

    artifact_dir = tmp_path / "reports" / "trusted-artifact"
    artifact_dir.mkdir(parents=True)
    archive = artifact_dir / "image.oci.tar"
    _write_verified_oci(archive)
    trusted = artifact_dir / "trusted-artifact.json"
    trusted.write_text(
        json.dumps(
            {
                "overall_status": "VERIFIED",
                "scout_status": "PASS",
                "context": ".abl-workspaces/agent-test/workspace",
                "oci_archive": "reports/trusted-artifact/image.oci.tar",
                "oci_archive_sha256": sha256_file(archive),
            }
        ),
        encoding="utf-8",
    )
    return run_dir / "session.json", trusted, archive


def test_lineage_binds_verified_agent_workspace_to_oci_artifact(tmp_path: Path):
    session, trusted, archive = _fixture(tmp_path)
    output = tmp_path / "reports" / "lineage.json"

    statement = create_lineage_statement(
        session,
        trusted,
        root_path=tmp_path,
        output=output,
    )

    assert statement["subject"][0]["digest"]["sha256"] == sha256_file(archive)
    artifact = statement["predicate"]["artifact"]
    assert artifact["ociGraphIntegrityVerified"] is True
    assert artifact["ociAttestationsVerified"] is True
    assert artifact["subjectBindingsValid"] is True

    ok, errors, _ = verify_lineage_statement(
        output,
        session,
        trusted,
        root_path=tmp_path,
    )
    assert ok is True
    assert errors == []


def test_lineage_rejects_workspace_mutation_after_agent_run(tmp_path: Path):
    session, trusted, _ = _fixture(tmp_path)
    workspace = tmp_path / ".abl-workspaces" / "agent-test" / "workspace"
    (workspace / "app.py").write_text("tampered\n", encoding="utf-8")

    with pytest.raises(ValueError, match="workspace digest"):
        create_lineage_statement(session, trusted, root_path=tmp_path)


def test_lineage_rejects_archive_mutation_after_trusted_report(tmp_path: Path):
    session, trusted, archive = _fixture(tmp_path)
    with archive.open("ab") as handle:
        handle.write(b"tamper")

    with pytest.raises(ValueError, match="archive digest"):
        create_lineage_statement(session, trusted, root_path=tmp_path)
