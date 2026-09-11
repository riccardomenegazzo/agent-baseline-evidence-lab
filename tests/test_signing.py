from __future__ import annotations

import json
import os

import pytest

from agent_baseline_lab import signing
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



@pytest.fixture
def signed_input(tmp_path):
    private, public = generate_keypair(tmp_path / "private.json", tmp_path / "public.json")
    subject = tmp_path / "subject.txt"
    subject.write_bytes(b"synthetic evidence\n")
    signature = tmp_path / "signature.json"
    sign_file(subject, private, signature)
    return private, public, subject, signature


@pytest.mark.parametrize("field,value", [
    ("schema_version", 999), ("schema_version", True), ("schema_version", "1"),
    ("schema_version", None), ("signature_type", "unknown"),
    ("signature_b64", "bad"), ("signature_b64", 1), ("signature_b64", ""),
    ("public_key_b64", "!"), ("public_key_b64", None),
    ("key_id", "ed25519:wrong"), ("subject_sha256", []), ("subject_path", None),
])
def test_verifier_rejects_unknown_or_malformed_metadata(signed_input, field, value):
    _, public, subject, signature = signed_input
    payload = json.loads(signature.read_text())
    payload[field] = value
    signature.write_text(json.dumps(payload))
    ok, errors, summary = verify_signature(subject, signature, public_key_path=public)
    assert not ok and errors and not summary["signature_valid"]


@pytest.mark.parametrize("data", [b"{", b"[]", b"null", b"1", b"\xff", b" " * 65537,
    b'{"schema_version":1,"schema_version":1}', b'{"schema_version":NaN}',
    b'[' * 2000 + b']' * 2000])
def test_verifier_returns_failure_for_unreadable_metadata(signed_input, data):
    _, public, subject, signature = signed_input
    signature.write_bytes(data)
    ok, errors, summary = verify_signature(subject, signature, public_key_path=public)
    assert not ok and errors and not summary["signature_valid"]


@pytest.mark.parametrize("which", ["subject", "signature", "public"])
def test_missing_inputs_return_failure(signed_input, which):
    _, public, subject, signature = signed_input
    {"subject": subject, "signature": signature, "public": public}[which].unlink()
    ok, errors, _ = verify_signature(subject, signature, public_key_path=public)
    assert not ok and errors


@pytest.mark.parametrize("field,value", [("schema_version", 99), ("key_id", "ed25519:wrong"), ("key_b64", "!")])
def test_external_key_metadata_is_validated(signed_input, field, value):
    _, public, subject, signature = signed_input
    payload = json.loads(public.read_text())
    payload[field] = value
    public.write_text(json.dumps(payload))
    assert verify_signature(subject, signature, public_key_path=public)[0] is False


def test_external_verification_rejects_inconsistent_embedded_key(signed_input, tmp_path):
    _, public, subject, signature = signed_input
    _, other = generate_keypair(tmp_path / "other-private", tmp_path / "other-public")
    payload = json.loads(signature.read_text())
    payload["public_key_b64"] = json.loads(other.read_text())["key_b64"]
    signature.write_text(json.dumps(payload))
    assert verify_signature(subject, signature, public_key_path=public)[0] is False


def test_keygen_never_overwrites_existing_pair(signed_input):
    private, public, subject, signature = signed_input
    before = (private.read_bytes(), public.read_bytes())
    with pytest.raises(ValueError, match="already exists"):
        generate_keypair(private, public)
    assert before == (private.read_bytes(), public.read_bytes())
    assert verify_signature(subject, signature, public_key_path=public)[0]


@pytest.mark.parametrize("existing", ["private", "public"])
def test_keygen_preserves_incomplete_pair_without_creating_other_file(tmp_path, existing):
    private, public = tmp_path / "private", tmp_path / "public"
    existing_path = {"private": private, "public": public}[existing]
    existing_path.write_text("keep")
    with pytest.raises(ValueError, match="already exists"):
        generate_keypair(private, public)
    assert existing_path.read_text() == "keep"
    assert len(list(tmp_path.iterdir())) == 1


def test_keygen_rejects_same_path_and_dangling_symlink(tmp_path):
    private, public = tmp_path / "private", tmp_path / "public"
    with pytest.raises(ValueError, match="different"):
        generate_keypair(private, private)
    private.symlink_to(tmp_path / "missing")
    with pytest.raises(ValueError, match="already exists"):
        generate_keypair(private, public)
    assert not public.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_private_key_is_owner_only_even_with_permissive_umask(tmp_path):
    previous = os.umask(0)
    try:
        private, _ = generate_keypair(tmp_path / "keys/private", tmp_path / "keys/public")
    finally:
        os.umask(previous)
    assert private.stat().st_mode & 0o777 == 0o600
    assert private.parent.stat().st_mode & 0o777 == 0o700


def test_failed_write_removes_only_new_pair(tmp_path, monkeypatch):
    private, public = tmp_path / "private", tmp_path / "public"
    def fail(fd):
        raise OSError("simulated write failure")
    monkeypatch.setattr(signing.os, "fsync", fail)
    with pytest.raises(OSError, match="simulated"):
        generate_keypair(private, public)
    assert not private.exists() and not public.exists()


def test_new_key_rotation_preserves_old_evidence(signed_input, tmp_path):
    _, old_public, subject, old_signature = signed_input
    private, public = generate_keypair(tmp_path / "v2/private", tmp_path / "v2/public")
    new_signature = tmp_path / "v2/signature"
    sign_file(subject, private, new_signature)
    assert verify_signature(subject, old_signature, public_key_path=old_public)[0]
    assert verify_signature(subject, new_signature, public_key_path=public)[0]
    assert not verify_signature(subject, old_signature, public_key_path=public)[0]


@pytest.mark.parametrize("alias", ["direct", "hardlink"])
def test_signing_cannot_overwrite_private_key(signed_input, tmp_path, alias):
    private, _, subject, _ = signed_input
    output = private
    if alias == "hardlink":
        output = tmp_path / "alias"
        output.hardlink_to(private)
    original = private.read_bytes()
    with pytest.raises(ValueError, match="must differ"):
        sign_file(subject, private, output)
    assert private.read_bytes() == original
