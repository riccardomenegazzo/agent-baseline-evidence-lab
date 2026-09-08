from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SignatureReceipt:
    schema_version: int
    artifact_type: str
    artifact: str
    artifact_sha256: str
    signature: str
    signature_sha256: str
    public_key: str
    public_key_sha256: str
    signer_identity: str
    signer_fingerprint: str
    namespace: str
    algorithm: str
    signed_at: str
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_ssh_keygen() -> str:
    executable = shutil.which("ssh-keygen")
    if not executable:
        raise RuntimeError("OpenSSH ssh-keygen is required for signing and verification")
    return executable


def public_key_fingerprint(public_key: str | Path) -> str:
    executable = _require_ssh_keygen()
    result = subprocess.run(
        [executable, "-lf", str(public_key), "-E", "sha256"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"unable to fingerprint public key: {result.stderr.strip()}")
    parts = result.stdout.strip().split()
    if len(parts) < 2:
        raise RuntimeError("ssh-keygen returned an unexpected fingerprint format")
    return parts[1]


def generate_keypair(
    private_key: str | Path,
    *,
    identity: str = "agent-baseline-evidence-lab",
) -> tuple[Path, Path, str]:
    executable = _require_ssh_keygen()
    private = Path(private_key)
    public = Path(str(private) + ".pub")
    if private.exists() or public.exists():
        raise FileExistsError("refusing to overwrite an existing signing keypair")
    private.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            executable,
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            identity,
            "-f",
            str(private),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"key generation failed: {result.stderr.strip()}")
    with contextlib.suppress(OSError):
        os.chmod(private, 0o600)
    return private, public, public_key_fingerprint(public)


def sign_artifact(
    artifact: str | Path,
    private_key: str | Path,
    *,
    public_key: str | Path | None = None,
    identity: str = "agent-baseline-evidence-lab",
    signature_path: str | Path | None = None,
    receipt_path: str | Path | None = None,
    namespace: str = "file",
) -> SignatureReceipt:
    executable = _require_ssh_keygen()
    artifact_path = Path(artifact).resolve()
    private = Path(private_key).resolve()
    public = Path(public_key).resolve() if public_key else Path(str(private) + ".pub")
    if not artifact_path.exists():
        raise FileNotFoundError(f"artifact not found: {artifact_path}")
    if not private.exists() or not public.exists():
        raise FileNotFoundError("signing private/public keypair is incomplete")

    signature = Path(signature_path) if signature_path else Path(str(artifact_path) + ".sig")
    receipt = Path(receipt_path) if receipt_path else Path(str(artifact_path) + ".signature.json")
    signature.parent.mkdir(parents=True, exist_ok=True)
    receipt.parent.mkdir(parents=True, exist_ok=True)

    default_signature = Path(str(artifact_path) + ".sig")
    if default_signature.exists():
        default_signature.unlink()
    result = subprocess.run(
        [executable, "-Y", "sign", "-n", namespace, "-f", str(private), str(artifact_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0 or not default_signature.exists():
        raise RuntimeError(f"ssh signing failed: {result.stderr.strip()}")
    if signature.resolve() != default_signature.resolve():
        shutil.move(str(default_signature), str(signature))

    payload = SignatureReceipt(
        schema_version=1,
        artifact_type="ssh-detached-signature",
        artifact=str(artifact_path),
        artifact_sha256=sha256_file(artifact_path),
        signature=str(signature.resolve()),
        signature_sha256=sha256_file(signature),
        public_key=str(public.resolve()),
        public_key_sha256=sha256_file(public),
        signer_identity=identity,
        signer_fingerprint=public_key_fingerprint(public),
        namespace=namespace,
        algorithm="ssh-ed25519",
        signed_at=_utc_now(),
        claims_boundary=(
            "Signature authenticity depends on independently trusting the recorded public-key "
            "fingerprint or key distribution channel; self-contained receipt verification alone "
            "does not establish signer identity."
        ),
    )
    receipt.write_text(json.dumps(payload.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def verify_artifact_signature(
    receipt_path: str | Path,
    *,
    artifact: str | Path | None = None,
    public_key: str | Path | None = None,
    expected_fingerprint: str | None = None,
) -> tuple[bool, list[str], dict[str, Any]]:
    executable = _require_ssh_keygen()
    receipt_file = Path(receipt_path)
    payload = json.loads(receipt_file.read_text(encoding="utf-8"))
    errors: list[str] = []
    if payload.get("schema_version") != 1 or payload.get("artifact_type") != "ssh-detached-signature":
        errors.append("unsupported signature receipt schema")

    artifact_path = Path(artifact or payload.get("artifact", ""))
    signature_path = Path(payload.get("signature", ""))
    public_path = Path(public_key or payload.get("public_key", ""))
    identity = str(payload.get("signer_identity", ""))
    namespace = str(payload.get("namespace", "file"))

    for label, path in (("artifact", artifact_path), ("signature", signature_path), ("public key", public_path)):
        if not path.exists():
            errors.append(f"{label} is missing: {path}")
    if errors:
        return False, errors, {"signature_verified": False}

    observed_artifact_sha = sha256_file(artifact_path)
    observed_signature_sha = sha256_file(signature_path)
    observed_public_sha = sha256_file(public_path)
    observed_fingerprint = public_key_fingerprint(public_path)
    if observed_artifact_sha != payload.get("artifact_sha256"):
        errors.append("artifact digest does not match signature receipt")
    if observed_signature_sha != payload.get("signature_sha256"):
        errors.append("signature digest does not match signature receipt")
    if observed_public_sha != payload.get("public_key_sha256"):
        errors.append("public key digest does not match signature receipt")
    if observed_fingerprint != payload.get("signer_fingerprint"):
        errors.append("public key fingerprint does not match signature receipt")
    if expected_fingerprint and observed_fingerprint != expected_fingerprint:
        errors.append("public key fingerprint does not match externally expected fingerprint")

    signature_verified = False
    if not errors:
        key_text = public_path.read_text(encoding="utf-8").strip()
        with tempfile.TemporaryDirectory(prefix="abl-signature-verify-") as temp_dir:
            allowed = Path(temp_dir) / "allowed_signers"
            allowed.write_text(f"{identity} {key_text}\n", encoding="utf-8")
            with artifact_path.open("rb") as message:
                result = subprocess.run(
                    [
                        executable,
                        "-Y",
                        "verify",
                        "-f",
                        str(allowed),
                        "-I",
                        identity,
                        "-n",
                        namespace,
                        "-s",
                        str(signature_path),
                    ],
                    stdin=message,
                    capture_output=True,
                    text=False,
                    timeout=60,
                    check=False,
                )
            signature_verified = result.returncode == 0
            if not signature_verified:
                stderr = result.stderr.decode("utf-8", errors="replace").strip()
                errors.append(f"OpenSSH signature verification failed: {stderr}")

    summary = {
        "signature_verified": signature_verified,
        "artifact_sha256": observed_artifact_sha,
        "signer_fingerprint": observed_fingerprint,
        "external_fingerprint_checked": bool(expected_fingerprint),
        "namespace": namespace,
    }
    return not errors and signature_verified, errors, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Portable OpenSSH signing for Agent Baseline evidence")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen")
    keygen.add_argument("private_key")
    keygen.add_argument("--identity", default="agent-baseline-evidence-lab")

    sign = sub.add_parser("sign")
    sign.add_argument("artifact")
    sign.add_argument("--private-key", required=True)
    sign.add_argument("--public-key", default=None)
    sign.add_argument("--identity", default="agent-baseline-evidence-lab")
    sign.add_argument("--signature", default=None)
    sign.add_argument("--receipt", default=None)

    verify = sub.add_parser("verify")
    verify.add_argument("receipt")
    verify.add_argument("--artifact", default=None)
    verify.add_argument("--public-key", default=None)
    verify.add_argument("--expected-fingerprint", default=None)

    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            private, public, fingerprint = generate_keypair(args.private_key, identity=args.identity)
            print(f"Private key: {private}")
            print(f"Public key: {public}")
            print(f"Fingerprint: {fingerprint}")
            return 0
        if args.command == "sign":
            receipt = sign_artifact(
                args.artifact,
                args.private_key,
                public_key=args.public_key,
                identity=args.identity,
                signature_path=args.signature,
                receipt_path=args.receipt,
            )
            print(json.dumps(receipt.to_dict(), indent=2, sort_keys=True))
            return 0
        ok, errors, summary = verify_artifact_signature(
            args.receipt,
            artifact=args.artifact,
            public_key=args.public_key,
            expected_fingerprint=args.expected_fingerprint,
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        for error in errors:
            print(f"ERROR: {error}")
        return 0 if ok else 1
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
