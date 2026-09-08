from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_baseline_lab.signing import (
    generate_keypair,
    sign_artifact,
    verify_artifact_signature,
)


pytestmark = pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen unavailable")


def test_sign_and_verify_with_external_fingerprint(tmp_path: Path) -> None:
    artifact = tmp_path / "evidence.json"
    artifact.write_text('{"ok": true}\n', encoding="utf-8")
    private, public, fingerprint = generate_keypair(tmp_path / "signing-key", identity="ci@example")
    receipt = sign_artifact(
        artifact,
        private,
        public_key=public,
        identity="ci@example",
        receipt_path=tmp_path / "evidence.signature.json",
    )
    ok, errors, summary = verify_artifact_signature(
        tmp_path / "evidence.signature.json",
        expected_fingerprint=fingerprint,
    )
    assert ok is True
    assert errors == []
    assert summary["signature_verified"] is True
    assert receipt.signer_fingerprint == fingerprint


def test_mutated_artifact_fails_verification(tmp_path: Path) -> None:
    artifact = tmp_path / "evidence.json"
    artifact.write_text("original\n", encoding="utf-8")
    private, public, _ = generate_keypair(tmp_path / "signing-key", identity="ci@example")
    sign_artifact(
        artifact,
        private,
        public_key=public,
        identity="ci@example",
        receipt_path=tmp_path / "evidence.signature.json",
    )
    artifact.write_text("mutated\n", encoding="utf-8")
    ok, errors, _ = verify_artifact_signature(tmp_path / "evidence.signature.json")
    assert ok is False
    assert any("artifact digest" in error for error in errors)


def test_wrong_external_fingerprint_fails(tmp_path: Path) -> None:
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("evidence\n", encoding="utf-8")
    private, public, _ = generate_keypair(tmp_path / "signing-key", identity="ci@example")
    sign_artifact(
        artifact,
        private,
        public_key=public,
        identity="ci@example",
        receipt_path=tmp_path / "evidence.signature.json",
    )
    ok, errors, _ = verify_artifact_signature(
        tmp_path / "evidence.signature.json",
        expected_fingerprint="SHA256:wrong",
    )
    assert ok is False
    assert any("externally expected fingerprint" in error for error in errors)
