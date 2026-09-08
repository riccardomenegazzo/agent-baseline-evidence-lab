from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from agent_baseline_lab import portable_pack


def _project(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "project"
    run_id = "abl-test"
    evidence = root / "evidence" / run_id
    evidence.mkdir(parents=True)
    (evidence / "assessment.json").write_text('{"run_id":"abl-test"}\n', encoding="utf-8")
    reports = root / "reports"
    reports.mkdir()
    (reports / f"{run_id}.json").write_text('{"run_id":"abl-test"}\n', encoding="utf-8")
    keys = root / ".abl" / "keys"
    keys.mkdir(parents=True)
    (keys / "attestation-public.json").write_text('{"type":"public-test"}\n', encoding="utf-8")
    (keys / "attestation-private.json").write_text('DO-NOT-EXPORT\n', encoding="utf-8")
    return root, run_id


def _trust_bundle(monkeypatch) -> None:
    monkeypatch.setattr(
        portable_pack,
        "verify_bundle",
        lambda path: (
            True,
            [],
            {
                "manifest_sha256": "manifest",
                "trace_head_sha256": "trace-head",
                "trace_event_count": 1,
            },
        ),
    )


def test_portable_pack_excludes_private_key_and_verifies(tmp_path: Path, monkeypatch) -> None:
    root, run_id = _project(tmp_path)
    _trust_bundle(monkeypatch)
    output = root / "reports" / "customer-evidence-pack.zip"

    pack_path, summary = portable_pack.create_pack(root, output_path=output, run_id=run_id)
    ok, errors, verification = portable_pack.verify_pack(pack_path)

    assert ok is True, errors
    assert verification["source_run_id"] == run_id
    assert summary.source_run_id == run_id

    with zipfile.ZipFile(pack_path, "r") as zf:
        names = set(zf.namelist())
        assert "trust/attestation-public.json" in names
        assert not any(name.endswith("attestation-private.json") for name in names)
        assert "pack-manifest.json" in names
        manifest = json.loads(zf.read("pack-manifest.json"))
        assert "private signing keys" in manifest["excluded_categories"]
        assert "host filesystem paths from incident manifests" in manifest["excluded_categories"]


def test_portable_pack_detects_member_tampering(tmp_path: Path, monkeypatch) -> None:
    root, run_id = _project(tmp_path)
    _trust_bundle(monkeypatch)
    original = root / "reports" / "customer-evidence-pack.zip"
    portable_pack.create_pack(root, output_path=original, run_id=run_id)

    tampered = root / "reports" / "customer-evidence-pack-tampered.zip"
    with zipfile.ZipFile(original, "r") as source, zipfile.ZipFile(tampered, "w") as target:
        for name in source.namelist():
            data = source.read(name)
            if name == f"evidence/{run_id}/assessment.json":
                data += b"tampered\n"
            target.writestr(name, data)

    ok, errors, _ = portable_pack.verify_pack(tampered)

    assert ok is False
    assert any("digest mismatch" in error for error in errors)


def test_portable_incident_uses_archive_paths_not_host_paths(tmp_path: Path, monkeypatch) -> None:
    root, run_id = _project(tmp_path)
    _trust_bundle(monkeypatch)
    response = root / ".abl" / "response" / "response.json"
    response.parent.mkdir(parents=True)
    response.write_text('{"verified_stopped":true}\n', encoding="utf-8")
    incident = root / "reports" / f"{run_id}.incident.json"
    incident.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "incident_id": "incident-test",
                "created_at": "2026-09-08T00:00:00+00:00",
                "source_run_id": run_id,
                "artifacts": [
                    {
                        "role": "response",
                        "path": str(response.resolve()),
                        "sha256": portable_pack.sha256_file(response),
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    pack_path, _ = portable_pack.create_pack(
        root,
        output_path=root / "reports" / "customer-evidence-pack.zip",
        run_id=run_id,
    )
    ok, errors, _ = portable_pack.verify_pack(pack_path)

    assert ok is True, errors
    with zipfile.ZipFile(pack_path, "r") as zf:
        manifest_bytes = zf.read("pack-manifest.json")
        incident_bytes = zf.read(f"reports/{run_id}.incident.json")
        assert str(root).encode() not in manifest_bytes
        assert str(root).encode() not in incident_bytes
        portable_incident = json.loads(incident_bytes)
        assert portable_incident["portable"] is True
        assert portable_incident["artifacts"][0]["path"] == ".abl/response/response.json"
        manifest = json.loads(manifest_bytes)
        assert "source_path" not in manifest["linked_incident_artifacts"][0]


def test_portable_pack_rejects_external_incident_artifact(tmp_path: Path, monkeypatch) -> None:
    root, run_id = _project(tmp_path)
    _trust_bundle(monkeypatch)
    outside = tmp_path / "outside-evidence.json"
    outside.write_text('{"external":true}\n', encoding="utf-8")
    incident = root / "reports" / f"{run_id}.incident.json"
    incident.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_run_id": run_id,
                "artifacts": [
                    {
                        "role": "external",
                        "path": str(outside),
                        "sha256": portable_pack.sha256_file(outside),
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="outside project root"):
        portable_pack.create_pack(
            root,
            output_path=root / "reports" / "customer-evidence-pack.zip",
            run_id=run_id,
        )
