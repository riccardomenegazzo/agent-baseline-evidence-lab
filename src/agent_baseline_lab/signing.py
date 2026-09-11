from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from contextlib import ExitStack
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

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
    return "ed25519:" + hashlib.sha256(public_key_raw).hexdigest()[:32]


def generate_keypair(private_key_path: str | Path, public_key_path: str | Path) -> tuple[Path, Path]:
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)
    if private_path.resolve() == public_path.resolve():
        raise ValueError("private and public key paths must be different")
    for path in (private_path, public_path):
        if path.exists() or path.is_symlink():
            raise ValueError("key destination already exists; use new paths for key rotation")

    private_key = Ed25519PrivateKey.generate()
    public_raw = _public_key_raw(private_key.public_key())
    payloads = (
        (private_path, 0o600, {
            "schema_version": 1, "type": "ed25519-private-key",
            "key_b64": base64.b64encode(_private_key_raw(private_key)).decode("ascii"),
        }),
        (public_path, 0o644, {
            "schema_version": 1, "type": "ed25519-public-key",
            "key_id": _key_id(public_raw),
            "key_b64": base64.b64encode(public_raw).decode("ascii"),
        }),
    )
    created: list[Path] = []
    try:
        with ExitStack() as stack:
            streams = []
            for path, mode, payload in payloads:
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                # Reserve both paths exclusively before writing any key material.
                # O_EXCL also rejects dangling symlinks and concurrent creators.
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
                created.append(path)
                stream = stack.enter_context(os.fdopen(fd, "w", encoding="utf-8"))
                if os.name == "posix":
                    os.fchmod(stream.fileno(), mode)
                streams.append((stream, payload))
            for stream, payload in streams:
                stream.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return private_path, public_path


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON field in signing metadata")
        result[name] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("non-finite JSON value in signing metadata")


def _read_metadata(path: str | Path) -> tuple[dict[str, Any], bytes]:
    with Path(path).open("rb") as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError("signing metadata exceeds 64 KiB")
    try:
        payload = json.loads(data, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except RecursionError as exc:
        raise ValueError("signing metadata is nested too deeply") from exc
    if not isinstance(payload, dict):
        raise ValueError("signing metadata must be a JSON object")
    if type(payload.get("schema_version")) is not int or payload["schema_version"] != 1:
        raise ValueError("unsupported signing metadata schema_version")
    return payload, data


def _base64_field(payload: dict[str, Any], name: str, length: int) -> bytes:
    value = payload.get(name)
    if not isinstance(value, str):
        raise ValueError(f"missing or invalid {name}")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError(f"invalid base64 in {name}") from exc
    if len(raw) != length:
        raise ValueError(f"invalid byte length in {name}")
    return raw


def _load_private_key(path: str | Path) -> Ed25519PrivateKey:
    payload, _ = _read_metadata(path)
    if payload.get("type") != "ed25519-private-key":
        raise ValueError("unsupported private key type")
    return Ed25519PrivateKey.from_private_bytes(_base64_field(payload, "key_b64", 32))


def _load_public_key(path: str | Path) -> tuple[Ed25519PublicKey, str]:
    payload, _ = _read_metadata(path)
    if payload.get("type") != "ed25519-public-key":
        raise ValueError("unsupported public key type")
    raw = _base64_field(payload, "key_b64", 32)
    key_id = _key_id(raw)
    if payload.get("key_id") != key_id:
        raise ValueError("public key_id does not match public key bytes")
    return Ed25519PublicKey.from_public_bytes(raw), key_id


def validate_keypair(private_key_path: str | Path, public_key_path: str | Path) -> str:
    """Validate the persisted pair without exposing private material."""
    private = _load_private_key(private_key_path)
    public, key_id = _load_public_key(public_key_path)
    if _public_key_raw(private.public_key()) != _public_key_raw(public):
        raise ValueError("private and public keys do not form a matching pair")
    return key_id


def sign_file(subject_path: str | Path, private_key_path: str | Path, output_path: str | Path) -> SignatureEnvelope:
    subject = Path(subject_path)
    output = Path(output_path)
    protected = (subject, Path(private_key_path))
    if any(
        output.resolve() == path.resolve()
        or (output.exists() and path.exists() and output.samefile(path))
        for path in protected
    ):
        raise ValueError("signature output must differ from the subject and private key")
    private_key = _load_private_key(private_key_path)
    public_key = private_key.public_key()
    public_raw = _public_key_raw(public_key)
    subject_bytes = subject.read_bytes()
    signature = private_key.sign(subject_bytes)
    envelope = SignatureEnvelope(
        schema_version=1,
        signature_type=SIGNATURE_TYPE,
        subject_path=subject.name,
        subject_sha256=hashlib.sha256(subject_bytes).hexdigest(),
        key_id=_key_id(public_raw),
        public_key_b64=base64.b64encode(public_raw).decode("ascii"),
        signature_b64=base64.b64encode(signature).decode("ascii"),
        claims_boundary=(
            "This signature authenticates the exact signed file relative to possession of the private key. "
            "It does not by itself establish who controls that key, completeness of upstream telemetry, or official conformance."
        ),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(envelope.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return envelope


def verify_signature(
    subject_path: str | Path,
    signature_path: str | Path,
    *,
    public_key_path: str | Path | None = None,
) -> tuple[bool, list[str], dict[str, Any]]:
    summary: dict[str, Any] = {
        "subject_sha256": "",
        "signature_sha256": "",
        "key_id": "",
        "public_key_external": public_key_path is not None,
        "signature_valid": False,
    }
    errors: list[str] = []
    try:
        payload, signature_bytes = _read_metadata(signature_path)
        summary["signature_sha256"] = hashlib.sha256(signature_bytes).hexdigest()
        if payload.get("signature_type") != SIGNATURE_TYPE:
            raise ValueError("unexpected signature type")
        if not isinstance(payload.get("subject_path"), str) or not payload["subject_path"]:
            raise ValueError("missing or invalid subject_path")
        embedded = _base64_field(payload, "public_key_b64", 32)
        embedded_key_id = _key_id(embedded)
        if payload.get("key_id") != embedded_key_id:
            raise ValueError("embedded public key does not match signature key_id")
        signature = _base64_field(payload, "signature_b64", 64)
        public_key = Ed25519PublicKey.from_public_bytes(embedded)
        expected_key_id = embedded_key_id
        if public_key_path is not None:
            public_key, expected_key_id = _load_public_key(public_key_path)
            if embedded != _public_key_raw(public_key):
                errors.append("signature key_id and embedded key do not match supplied public key")
        summary["key_id"] = expected_key_id
        # Hash and verify one snapshot, so a changing file cannot mix two reads.
        subject_bytes = Path(subject_path).read_bytes()
        summary["subject_sha256"] = hashlib.sha256(subject_bytes).hexdigest()
        if payload.get("subject_sha256") != summary["subject_sha256"]:
            errors.append("signed subject digest mismatch")
        public_key.verify(signature, subject_bytes)
    except InvalidSignature:
        errors.append("Ed25519 signature verification failed")
    except (OSError, ValueError, RecursionError) as exc:
        errors.append(f"invalid signing input: {exc}")
    summary["signature_valid"] = not errors
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

