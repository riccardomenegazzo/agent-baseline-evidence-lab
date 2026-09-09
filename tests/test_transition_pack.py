import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

from agent_baseline_lab.evidence import EvidenceStore, sha256_file
from agent_baseline_lab.models import Result, RunReport, Status
from agent_baseline_lab.provenance import write_run_attestation
from agent_baseline_lab.signing import generate_keypair
from agent_baseline_lab.trace import TraceLedger
from agent_baseline_lab.transition_pack import (
    create_transition_pack,
    verify_transition_pack,
)
from agent_baseline_lab.trusted_artifact import SPDX_PREDICATE


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write_oci(path: Path, *, layer_content: bytes) -> None:
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
                        "digest": {"sha256": "a" * 64},
                    }
                ]
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
    with tarfile.open(path, "w") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))


def _trusted_report(path: Path, archive: Path) -> Path:
    payload = {
        "schema_version": 1,
        "overall_status": "VERIFIED",
        "oci_archive": archive.relative_to(path.parents[1]).as_posix(),
        "oci_archive_sha256": sha256_file(archive),
        "scout_status": "PASS",
        "checks": [
            {
                "id": "base-image-identity",
                "status": "PASS",
                "summary": "base observed",
                "evidence": {
                    "external_bases": ["python:3.13-slim"],
                    "digest_pinned": [],
                    "tag_only": ["python:3.13-slim"],
                },
            }
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _run(root: Path, run_id: str, status: Status) -> Path:
    evidence = root / "evidence" / run_id
    evidence.mkdir(parents=True)
    ledger = TraceLedger(evidence / "trace" / "events.ndjson", run_id)
    ledger.append("assessment.started", actor="lab", action="assess")
    ledger.append("assessment.completed", actor="lab", action="finalize")
    assessment = {
        "run_id": run_id,
        "baseline_version": "1.0-draft",
        "config_path": "examples/agent.yaml",
        "metadata": {
            "agent_id": "customer-agent",
            "trace_head_sha256": ledger.head_hash,
            "trace_event_count": ledger.sequence,
        },
        "results": [
            {
                "control_id": "C-01",
                "status": status.value,
                "summary": "test",
                "details": [],
                "evidence": [],
                "evaluator": "test",
            }
        ],
    }
    (evidence / "assessment.json").write_text(
        json.dumps(assessment, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest = EvidenceStore(evidence).finalize_manifest()
    reports = root / "reports"
    reports.mkdir(exist_ok=True)
    report = RunReport(
        run_id=run_id,
        started_at="2026-09-08T00:00:00+00:00",
        completed_at="2026-09-08T00:01:00+00:00",
        baseline_version="1.0-draft",
        config_path="examples/agent.yaml",
        results=[Result(control_id="C-01", status=status, summary="test")],
        metadata={
            "agent_id": "customer-agent",
            "trace_head_sha256": ledger.head_hash,
            "trace_event_count": ledger.sequence,
        },
    )
    (reports / f"{run_id}.json").write_text(
        json.dumps(report.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )
    write_run_attestation(
        report,
        manifest_path=manifest,
        context={},
        output_path=reports / f"{run_id}.attestation.json",
    )
    return evidence


def _keys(root: Path) -> tuple[Path, Path]:
    private = root / ".abl" / "keys" / "attestation-private.json"
    public = root / ".abl" / "keys" / "attestation-public.json"
    generate_keypair(private, public)
    return private, public


def _fixture(root: Path) -> tuple[Path, Path, Path, Path, Path]:
    before_evidence = _run(root, "abl-before", Status.PARTIAL)
    after_evidence = _run(root, "abl-after", Status.PASS)
    before_archive = root / "artifacts" / "before.oci.tar"
    after_archive = root / "artifacts" / "after.oci.tar"
    before_archive.parent.mkdir(parents=True)
    _write_oci(before_archive, layer_content=b"layer-before")
    _write_oci(after_archive, layer_content=b"layer-after")
    before_report = _trusted_report(root / "reports" / "before-trusted.json", before_archive)
    after_report = _trusted_report(root / "reports" / "after-trusted.json", after_archive)
    _, public = _keys(root)
    return before_evidence, after_evidence, before_report, after_report, public


def test_transition_pack_verifies_portably_and_with_full_oci_recomputation(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    before_evidence, after_evidence, before_report, after_report, public = _fixture(root)
    output = root / "reports" / "remediation-transition.zip"

    pack, signature, summary = create_transition_pack(
        root,
        before_evidence,
        after_evidence,
        before_report,
        after_report,
        output_path=output,
    )
    portable_ok, portable_errors, portable = verify_transition_pack(
        pack,
        signature_path=signature,
        public_key_path=public,
    )
    full_ok, full_errors, full = verify_transition_pack(
        pack,
        signature_path=signature,
        public_key_path=public,
        before_trusted_artifact=before_report,
        after_trusted_artifact=after_report,
        root_path=root,
    )

    assert portable_ok is True, portable_errors
    assert full_ok is True, full_errors
    assert summary.before_run_id == "abl-before"
    assert summary.after_run_id == "abl-after"
    assert summary.artifact_classification == "ARTIFACT_CHANGED"
    assert portable["source_report_bindings"] == {"before": True, "after": True}
    assert portable["artifact_recomputed"] is False
    assert portable["governance_comparison"]["delta"]["change_counts"] == {
        "control-improvement": 1
    }
    assert full["artifact_recomputed"] is True
    assert full["artifact_recomputation"]["classification"] == "ARTIFACT_CHANGED"
    assert full["pack_signature"]["signature_valid"] is True

    with zipfile.ZipFile(pack) as zf:
        names = set(zf.namelist())
        assert "governance/comparison-pack.zip" in names
        assert "artifact/oci-artifact-diff.json" in names
        assert "artifact/before-trusted-artifact.json" in names
        assert "artifact/after-trusted-artifact.json" in names
        assert "trust/attestation-public.json" in names
        assert not any(name.endswith("attestation-private.json") for name in names)


def test_transition_pack_detects_embedded_report_tampering(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    before_evidence, after_evidence, before_report, after_report, _ = _fixture(root)
    original = root / "reports" / "remediation-transition.zip"
    create_transition_pack(
        root,
        before_evidence,
        after_evidence,
        before_report,
        after_report,
        output_path=original,
    )
    tampered = root / "reports" / "remediation-transition-tampered.zip"
    with zipfile.ZipFile(original, "r") as source, zipfile.ZipFile(tampered, "w") as target:
        for name in source.namelist():
            data = source.read(name)
            if name == "artifact/before-trusted-artifact.json":
                data += b"tampered"
            target.writestr(name, data)

    ok, errors, _ = verify_transition_pack(tampered)

    assert ok is False
    assert any("digest mismatch" in error for error in errors)
    assert any("does not match signed artifact diff" in error for error in errors)


def test_transition_pack_requires_both_reports_for_full_recomputation(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    before_evidence, after_evidence, before_report, after_report, _ = _fixture(root)
    output = root / "reports" / "remediation-transition.zip"
    pack, _, _ = create_transition_pack(
        root,
        before_evidence,
        after_evidence,
        before_report,
        after_report,
        output_path=output,
    )

    ok, errors, details = verify_transition_pack(
        pack,
        before_trusted_artifact=before_report,
        root_path=root,
    )

    assert ok is False
    assert details["artifact_recomputed"] is False
    assert errors == [
        "both before_trusted_artifact and after_trusted_artifact are required for full OCI recomputation"
    ]
