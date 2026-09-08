from __future__ import annotations

import argparse
import base64
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .evidence import sha256_file

SIGNATURE_TYPE = "https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/signature/ed25519/v1"


@dataclass(frozen=True)
class SignatureEnvelope:
    schema_version: int
    signature_type: str
    subject_path: str
    subject_sha256: str
    key_id: str
    public_key_b64: str
    signature_b64: str
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _public_key_raw(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _private_key_raw(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _key_id(public_key_raw: bytes) -> str:
    import hashlib

    return "ed25519:" + hashlib.sha256(public_key_raw).hexdigest()[:32]


def generate_keypair(private_key_path: str | Path, public_key_path: str | Path) -> tuple[Path, Path]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "type": "ed25519-private-key",
                "key_b64": base64.b64encode(_private_key_raw(private_key)).decode("ascii"),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    public_raw = _public_key_raw(public_key)
    public_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "type": "ed25519-public-key",
                "key_id": _key_id(public_raw),
                "key_b64": base64.b64encode(public_raw).decode("ascii"),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return private_path, public_path


def _load_private_key(path: str | Path) -> Ed25519PrivateKey:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("type") != "ed25519-private-key":
        raise ValueError("unsupported private key type")
    raw = base64.b64decode(str(payload.get("key_b64", "")), validate=True)
    if len(raw) != 32:
        raise ValueError("invalid Ed25519 private key length")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _load_public_key(path: str | Path) -> tuple[Ed25519PublicKey, str]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("type") != "ed25519-public-key":
        raise ValueError("unsupported public key type")
    raw = base64.b64decode(str(payload.get("key_b64", "")), validate=True)
    if len(raw) != 32:
        raise ValueError("invalid Ed25519 public key length")
    key_id = str(payload.get("key_id", "")) or _key_id(raw)
    return Ed25519PublicKey.from_public_bytes(raw), key_id


def sign_file(subject_path: str | Path, private_key_path: str | Path, output_path: str | Path) -> SignatureEnvelope:
    subject = Path(subject_path)
    private_key = _load_private_key(private_key_path)
    public_key = private_key.public_key()
    public_raw = _public_key_raw(public_key)
    subject_bytes = subject.read_bytes()
    signature = private_key.sign(subject_bytes)
    envelope = SignatureEnvelope(
        schema_version=1,
        signature_type=SIGNATURE_TYPE,
        subject_path=subject.name,
        subject_sha256=sha256_file(subject),
        key_id=_key_id(public_raw),
        public_key_b64=base64.b64encode(public_raw).decode("ascii"),
        signature_b64=base64.b64encode(signature).decode("ascii"),
        claims_boundary=(
            "This signature authenticates the exact signed file relative to possession of the private key. "
            "It does not by itself establish who controls that key, completeness of upstream telemetry, or official conformance."
        ),
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(envelope.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return envelope


def verify_signature(
    subject_path: str | Path,
    signature_path: str | Path,
    *,
    public_key_path: str | Path | None = None,
) -> tuple[bool, list[str], dict[str, Any]]:
    subject = Path(subject_path)
    signature_file = Path(signature_path)
    errors: list[str] = []
    payload = json.loads(signature_file.read_text(encoding="utf-8"))
    if payload.get("signature_type") != SIGNATURE_TYPE:
        errors.append("unexpected signature type")
    observed_sha256 = sha256_file(subject) if subject.exists() else ""
    if not observed_sha256:
        errors.append("signed subject is missing")
    if str(payload.get("subject_sha256", "")) != observed_sha256:
        errors.append("signed subject digest mismatch")

    if public_key_path is not None:
        public_key, expected_key_id = _load_public_key(public_key_path)
        if str(payload.get("key_id", "")) != expected_key_id:
            errors.append("signature key_id does not match supplied public key")
    else:
        raw = base64.b64decode(str(payload.get("public_key_b64", "")), validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(raw)
        expected_key_id = _key_id(raw)
        if str(payload.get("key_id", "")) != expected_key_id:
            errors.append("embedded public key does not match signature key_id")

    try:
        signature = base64.b64decode(str(payload.get("signature_b64", "")), validate=True)
        public_key.verify(signature, subject.read_bytes())
    except (InvalidSignature, ValueError):
        errors.append("Ed25519 signature verification failed")

    summary = {
        "subject_sha256": observed_sha256,
        "signature_sha256": sha256_file(signature_file),
        "key_id": expected_key_id,
        "public_key_external": public_key_path is not None,
        "signature_valid": not errors,
    }
    return not errors, errors, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate keys, sign, or verify Agent Baseline evidence artifacts")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen")
    keygen.add_argument("--private", default=".abl/keys/attestation-private.json")
    keygen.add_argument("--public", default=".abl/keys/attestation-public.json")

    sign = sub.add_parser("sign")
    sign.add_argument("subject")
    sign.add_argument("--private", required=True)
    sign.add_argument("--output", required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("subject")
    verify.add_argument("signature")
    verify.add_argument("--public", default=None)

    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            private_path, public_path = generate_keypair(args.private, args.public)
            print(f"Private key: {private_path}")
            print(f"Public key:  {public_path}")
            return 0
        if args.command == "sign":
            envelope = sign_file(args.subject, args.private, args.output)
            print(json.dumps(envelope.to_dict(), indent=2, sort_keys=True))
            return 0
        ok, errors, summary = verify_signature(args.subject, args.signature, public_key_path=args.public)
        print(json.dumps(summary, indent=2, sort_keys=True))
        for error in errors:
            print(f"ERROR: {error}")
        return 0 if ok else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
