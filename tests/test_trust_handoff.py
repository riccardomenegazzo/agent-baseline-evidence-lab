from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from agent_baseline_lab.signing import generate_keypair, sign_file
from agent_baseline_lab.trust_handoff import create_handoff_pack, verify_handoff_pack


def _minimal_customer_pack(path: Path, run_id: str) -> None:
    manifest = {
        "schema_version": 1,
        "source_run_id": run_id,
        "files": [],
        "linked_incident_artifacts": [],
        "excluded_categories": ["private signing keys"],
        "claims_boundary": "test fixture",
    }
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("pack-manifest.json", json.dumps(manifest))


def _fixture(tmp_path: Path) -> tuple[Path, str, list[tuple[str, Path, str]]]:
    root = tmp_path / "project"
    reports = root / "reports"
    keys = root / ".abl" / "keys"
    reports.mkdir(parents=True)
    keys.mkdir(parents=True)
    run_id = "abl-trust-test"

    private_key, public_key = generate_keypair(
        keys / "attestation-private.json",
        keys / "attestation-public.json",
    )
    golden = reports / f"{run_id}.customer-evidence-pack.zip"
    _minimal_customer_pack(golden, run_id)
    golden_sig = reports / f"{run_id}.customer-evidence-pack.zip.ed25519.json"
    sign_file(golden, private_key, golden_sig)

    decision = reports / f"{run_id}.decision.json"
    decision.write_text('{"decision":"EVIDENCE_READY"}\n', encoding="utf-8")
    trusted = reports / f"{run_id}.trusted-artifact.portable.json"
    trusted.write_text(
        '{"overall_status":"VERIFIED","oci_archive_sha256":"abc"}\n',
        encoding="utf-8",
    )
    sarif = reports / f"{run_id}.sarif"
    sarif.write_text('{"version":"2.1.0","runs":[]}\n', encoding="utf-8")

    sources = [
        ("golden-customer-pack", golden, "evidence/customer-evidence-pack.zip"),
        (
            "golden-customer-pack-signature",
            golden_sig,
            "evidence/customer-evidence-pack.zip.ed25519.json",
        ),
        ("public-verification-key", public_key, "trust/attestation-public.json"),
        ("customer-decision", decision, "decision/customer-decision.json"),
        ("trusted-artifact", trusted, "supply-chain/trusted-artifact.json"),
        ("sarif", sarif, "integrations/agent-governance.sarif"),
    ]
    return root, run_id, sources


def test_handoff_verifies_nested_customer_pack_and_signature(tmp_path: Path) -> None:
    root, run_id, sources = _fixture(tmp_path)
    output = root / "reports" / f"{run_id}.customer-trust-handoff.zip"

    pack, summary = create_handoff_pack(
        root,
        run_id=run_id,
        output_path=output,
        dry_run=False,
        sources=sources,
    )
    ok, errors, details = verify_handoff_pack(pack)

    assert ok is True, errors
    assert summary.source_run_id == run_id
    assert details["nested_customer_pack_verified"] is True
    assert details["nested_customer_pack_signature_verified"] is True
    with zipfile.ZipFile(pack, "r") as zf:
        names = set(zf.namelist())
        assert "handoff-manifest.json" in names
        assert not any("private" in name for name in names)
        assert not any(name.endswith(".oci.tar") for name in names)


def test_handoff_detects_member_tampering(tmp_path: Path) -> None:
    root, run_id, sources = _fixture(tmp_path)
    original = root / "reports" / "original.zip"
    create_handoff_pack(
        root,
        run_id=run_id,
        output_path=original,
        dry_run=False,
        sources=sources,
    )
    tampered = root / "reports" / "tampered.zip"
    with zipfile.ZipFile(original, "r") as source, zipfile.ZipFile(tampered, "w") as target:
        for name in source.namelist():
            data = source.read(name)
            if name == "decision/customer-decision.json":
                data += b"tamper"
            target.writestr(name, data)

    ok, errors, _ = verify_handoff_pack(tampered)

    assert ok is False
    assert any("digest mismatch" in error for error in errors)


def test_handoff_rejects_local_path_leakage(tmp_path: Path) -> None:
    root, run_id, sources = _fixture(tmp_path)
    leaked = root / "reports" / "leaked.json"
    leaked.write_text(json.dumps({"workspace": str(root / ".abl-workspaces" / "agent")}), encoding="utf-8")
    sources.append(("leaked", leaked, "leaked.json"))

    with pytest.raises(ValueError, match="local filesystem path marker"):
        create_handoff_pack(
            root,
            run_id=run_id,
            output_path=root / "reports" / "handoff.zip",
            dry_run=False,
            sources=sources,
        )


def test_handoff_rejects_oci_image_archive(tmp_path: Path) -> None:
    root, run_id, sources = _fixture(tmp_path)
    archive = root / "reports" / "image.oci.tar"
    archive.write_bytes(b"not-an-image")
    sources.append(("oci-image", archive, "supply-chain/image.oci.tar"))

    with pytest.raises(ValueError, match="OCI image archives"):
        create_handoff_pack(
            root,
            run_id=run_id,
            output_path=root / "reports" / "handoff.zip",
            dry_run=False,
            sources=sources,
        )
