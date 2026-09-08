from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .signing import public_key_fingerprint, sha256_file

DEFAULT_REKOR_SERVER = "https://rekor.sigstore.dev"


@dataclass(frozen=True)
class RekorReceipt:
    schema_version: int
    artifact_type: str
    artifact_sha256: str
    signature_sha256: str
    public_key_sha256: str
    signer_fingerprint: str
    rekor_server: str
    entry_url: str
    entry_uuid: str
    log_index: int | None
    published_at: str
    command_output_sha256: str
    inclusion_verified: bool
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _require_rekor_cli() -> str:
    executable = shutil.which("rekor-cli")
    if not executable:
        raise RuntimeError("rekor-cli is required for transparency-log publication")
    return executable


def parse_upload_output(output: str) -> tuple[str, str, int | None]:
    url_match = re.search(r"https?://\S+/api/v1/log/entries/([0-9A-Fa-f]+)", output)
    index_match = re.search(r"(?:index|Index)\s*[: ]\s*(\d+)", output)
    if not url_match:
        raise ValueError("rekor-cli output did not contain an entry URL")
    entry_url = url_match.group(0).rstrip(".,)")
    uuid = url_match.group(1)
    index = int(index_match.group(1)) if index_match else None
    return entry_url, uuid, index


def publish_ssh_signature(
    artifact: str | Path,
    signature: str | Path,
    public_key: str | Path,
    *,
    output_path: str | Path,
    rekor_server: str = DEFAULT_REKOR_SERVER,
    dry_run: bool = False,
) -> RekorReceipt:
    artifact_path = Path(artifact).resolve()
    signature_path = Path(signature).resolve()
    public_path = Path(public_key).resolve()
    for label, path in (("artifact", artifact_path), ("signature", signature_path), ("public key", public_path)):
        if not path.exists():
            raise FileNotFoundError(f"{label} not found: {path}")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if dry_run:
        receipt = RekorReceipt(
            schema_version=1,
            artifact_type="rekor-transparency-receipt",
            artifact_sha256=sha256_file(artifact_path),
            signature_sha256=sha256_file(signature_path),
            public_key_sha256=sha256_file(public_path),
            signer_fingerprint=public_key_fingerprint(public_path),
            rekor_server=rekor_server,
            entry_url="",
            entry_uuid="",
            log_index=None,
            published_at=_utc_now(),
            command_output_sha256=_sha256_text(""),
            inclusion_verified=False,
            claims_boundary="Dry run: no Rekor entry was created or verified.",
        )
        output.write_text(json.dumps(receipt.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return receipt

    executable = _require_rekor_cli()
    command = [
        executable,
        "upload",
        "--rekor_server",
        rekor_server,
        "--artifact",
        str(artifact_path),
        "--signature",
        str(signature_path),
        "--pki-format=ssh",
        "--public-key",
        str(public_path),
    ]
    upload = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    combined = "\n".join(part for part in (upload.stdout, upload.stderr) if part)
    if upload.returncode != 0:
        raise RuntimeError(f"rekor upload failed: {combined.strip()}")
    entry_url, entry_uuid, log_index = parse_upload_output(combined)

    verify = subprocess.run(
        [
            executable,
            "verify",
            "--rekor_server",
            rekor_server,
            "--artifact",
            str(artifact_path),
            "--signature",
            str(signature_path),
            "--pki-format=ssh",
            "--public-key",
            str(public_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    inclusion_verified = verify.returncode == 0
    verify_output = "\n".join(part for part in (verify.stdout, verify.stderr) if part)
    receipt = RekorReceipt(
        schema_version=1,
        artifact_type="rekor-transparency-receipt",
        artifact_sha256=sha256_file(artifact_path),
        signature_sha256=sha256_file(signature_path),
        public_key_sha256=sha256_file(public_path),
        signer_fingerprint=public_key_fingerprint(public_path),
        rekor_server=rekor_server,
        entry_url=entry_url,
        entry_uuid=entry_uuid,
        log_index=log_index,
        published_at=_utc_now(),
        command_output_sha256=_sha256_text(combined + "\n" + verify_output),
        inclusion_verified=inclusion_verified,
        claims_boundary=(
            "Receipt proves the submitted artifact/signature/public-key tuple was accepted by the "
            "configured Rekor log and, when inclusion_verified is true, rekor-cli verified its proof. "
            "Trust still depends on the selected Rekor server and independently trusted signer key."
        ),
    )
    output.write_text(json.dumps(receipt.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Publish signed Agent Baseline evidence to Sigstore Rekor")
    parser.add_argument("artifact")
    parser.add_argument("--signature", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--rekor-server", default=DEFAULT_REKOR_SERVER)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        receipt = publish_ssh_signature(
            args.artifact,
            args.signature,
            args.public_key,
            output_path=args.output,
            rekor_server=args.rekor_server,
            dry_run=args.dry_run,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(receipt.to_dict(), indent=2, sort_keys=True))
    return 0 if args.dry_run or receipt.inclusion_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
