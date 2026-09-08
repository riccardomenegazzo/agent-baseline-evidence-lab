from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_baseline_lab.rekor import parse_upload_output, publish_ssh_signature
from agent_baseline_lab.signing import generate_keypair, sign_artifact


def test_parse_upload_output() -> None:
    url, uuid, index = parse_upload_output(
        "Created entry at index 5896, available at: "
        "https://rekor.sigstore.dev/api/v1/log/entries/0e81b4d9299e2609e45b5c453a4c0e78"
    )
    assert uuid == "0e81b4d9299e2609e45b5c453a4c0e78"
    assert index == 5896
    assert url.endswith(uuid)


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen unavailable")
def test_rekor_dry_run_never_claims_inclusion(tmp_path: Path) -> None:
    artifact = tmp_path / "bundle.json"
    artifact.write_text('{"bundle": true}\n', encoding="utf-8")
    private, public, _ = generate_keypair(tmp_path / "key", identity="ci@example")
    signed = sign_artifact(
        artifact,
        private,
        public_key=public,
        identity="ci@example",
        receipt_path=tmp_path / "signature.json",
    )
    receipt = publish_ssh_signature(
        artifact,
        signed.signature,
        public,
        output_path=tmp_path / "rekor.json",
        dry_run=True,
    )
    assert receipt.inclusion_verified is False
    assert receipt.entry_uuid == ""
    assert receipt.entry_url == ""
