from __future__ import annotations

import json
from pathlib import Path

from agent_baseline_lab.signing import generate_keypair, sign_file, verify_signature


def test_ed25519_signature_round_trip_and_negative_cases(tmp_path: Path) -> None:
    private_key = tmp_path / "private.json"
    public_key = tmp_path / "public.json"
    wrong_private_key = tmp_path / "wrong-private.json"
    wrong_public_key = tmp_path / "wrong-public.json"
    subject = tmp_path / "attestation.json"
    signature = tmp_path / "attestation.sig.json"

    subject.write_text(json.dumps({"run": "abl-test", "value": 1}) + "\n", encoding="utf-8")
    generate_keypair(private_key, public_key)
    generate_keypair(wrong_private_key, wrong_public_key)

    envelope = sign_file(subject, private_key, signature)
    assert envelope.subject_sha256
    assert envelope.key_id.startswith("ed25519:")

    ok, errors, summary = verify_signature(subject, signature, public_key_path=public_key)
    assert ok is True
    assert errors == []
    assert summary["signature_valid"] is True
    assert summary["public_key_external"] is True

    # The embedded key supports self-contained verification, but an externally
    # provisioned public key is the stronger trust boundary.
    embedded_ok, embedded_errors, _ = verify_signature(subject, signature)
    assert embedded_ok is True
    assert embedded_errors == []

    subject.write_text(json.dumps({"run": "abl-test", "value": 2}) + "\n", encoding="utf-8")
    mutated_ok, mutated_errors, _ = verify_signature(subject, signature, public_key_path=public_key)
    assert mutated_ok is False
    assert any("digest mismatch" in error or "verification failed" in error for error in mutated_errors)

    # Restore the exact signed bytes and prove an unrelated public key cannot verify it.
    subject.write_text(json.dumps({"run": "abl-test", "value": 1}) + "\n", encoding="utf-8")
    wrong_ok, wrong_errors, _ = verify_signature(subject, signature, public_key_path=wrong_public_key)
    assert wrong_ok is False
    assert any("key_id" in error or "verification failed" in error for error in wrong_errors)
