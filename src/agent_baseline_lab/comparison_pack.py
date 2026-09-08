from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .evidence import sha256_file
from .governance_delta import (
    build_delta,
    verify_delta,
    write_delta_html,
    write_delta_json,
)
from .portable_pack import create_pack, verify_pack
from .provenance import verify_run_attestation
from .signing import sign_file, verify_signature


@dataclass(frozen=True)
class ComparisonMember:
    path: str
    role: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ComparisonPackSummary:
    schema_version: int
    before_run_id: str
    after_run_id: str
    members: list[ComparisonMember]
    signing_key_id: str
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "before_run_id": self.before_run_id,
            "after_run_id": self.after_run_id,
            "members": [item.to_dict() for item in self.members],
            "signing_key_id": self.signing_key_id,
            "claims_boundary": self.claims_boundary,
        }


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_member(name: str) -> str:
    pure = PurePosixPath(name)
    if not name or pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe comparison-pack member path: {name}")
    return pure.as_posix()


def _zip_write(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(_validate_member(name), date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    zf.writestr(info, data)


def _required_keypair(root: Path) -> tuple[Path, Path]:
    private_key = root / ".abl" / "keys" / "attestation-private.json"
    public_key = root / ".abl" / "keys" / "attestation-public.json"
    missing = [
        path.relative_to(root).as_posix()
        for path in (private_key, public_key)
        if not path.is_file()
    ]
    if missing:
        raise ValueError(
            "comparison handoff requires an Ed25519 keypair; run `make signing-keygen` first. "
            "Missing: " + ", ".join(missing)
        )
    return private_key, public_key


def _sign_run_attestation(
    root: Path,
    evidence_dir: Path,
    private_key: Path,
    public_key: Path,
) -> Path:
    run_id = evidence_dir.name
    attestation = root / "reports" / f"{run_id}.attestation.json"
    manifest = evidence_dir / "manifest.sha256.json"
    if not attestation.is_file():
        raise ValueError(f"run attestation is missing for {run_id}")
    attestation_ok, attestation_errors, _ = verify_run_attestation(attestation, manifest)
    if not attestation_ok:
        raise ValueError(
            f"run attestation does not bind to {run_id}: " + "; ".join(attestation_errors)
        )
    signature = root / "reports" / f"{run_id}.attestation.json.ed25519.json"
    sign_file(attestation, private_key, signature)
    signature_ok, signature_errors, _ = verify_signature(
        attestation,
        signature,
        public_key_path=public_key,
    )
    if not signature_ok:
        raise ValueError(
            f"run attestation signature failed for {run_id}: " + "; ".join(signature_errors)
        )
    return signature


def _key_id(public_key: Path) -> str:
    payload = json.loads(public_key.read_text(encoding="utf-8"))
    key_id = str(payload.get("key_id", "")).strip()
    if not key_id:
        raise ValueError("public verification key is missing key_id")
    return key_id


def create_comparison_pack(
    root_path: str | Path,
    before_dir: str | Path,
    after_dir: str | Path,
    *,
    output_path: str | Path,
) -> tuple[Path, Path, ComparisonPackSummary]:
    root = Path(root_path).resolve()
    before = Path(before_dir).resolve()
    after = Path(after_dir).resolve()
    private_key, public_key = _required_keypair(root)

    delta = build_delta(before, after)
    before_run = delta.before.run_id
    after_run = delta.after.run_id

    _sign_run_attestation(root, before, private_key, public_key)
    if after != before:
        _sign_run_attestation(root, after, private_key, public_key)

    with tempfile.TemporaryDirectory(prefix="abl-comparison-create-") as temp_dir:
        temp = Path(temp_dir)
        before_pack = temp / "before.zip"
        after_pack = temp / "after.zip"
        create_pack(root, output_path=before_pack, run_id=before_run)
        if after == before:
            after_pack.write_bytes(before_pack.read_bytes())
        else:
            create_pack(root, output_path=after_pack, run_id=after_run)

        for label, pack in (("before", before_pack), ("after", after_pack)):
            ok, errors, _ = verify_pack(pack)
            if not ok:
                raise ValueError(
                    f"{label} customer evidence pack failed verification: " + "; ".join(errors)
                )

        delta_json = temp / "governance-delta.json"
        delta_html = temp / "governance-delta.html"
        delta_signature = temp / "governance-delta.json.ed25519.json"
        write_delta_json(delta, delta_json)
        write_delta_html(delta, delta_html)
        sign_file(delta_json, private_key, delta_signature)
        delta_sig_ok, delta_sig_errors, delta_sig_summary = verify_signature(
            delta_json,
            delta_signature,
            public_key_path=public_key,
        )
        if not delta_sig_ok:
            raise ValueError(
                "governance delta signature failed: " + "; ".join(delta_sig_errors)
            )

        member_data: dict[str, tuple[bytes, str]] = {
            "before/customer-evidence-pack.zip": (before_pack.read_bytes(), "before-pack"),
            "after/customer-evidence-pack.zip": (after_pack.read_bytes(), "after-pack"),
            "comparison/governance-delta.json": (delta_json.read_bytes(), "governance-delta"),
            "comparison/governance-delta.html": (delta_html.read_bytes(), "governance-delta-html"),
            "comparison/governance-delta.json.ed25519.json": (
                delta_signature.read_bytes(),
                "governance-delta-signature",
            ),
            "trust/attestation-public.json": (public_key.read_bytes(), "public-verification-key"),
        }
        members = [
            ComparisonMember(
                path=name,
                role=role,
                sha256=_sha256_bytes(data),
                size=len(data),
            )
            for name, (data, role) in sorted(member_data.items())
        ]
        summary = ComparisonPackSummary(
            schema_version=1,
            before_run_id=before_run,
            after_run_id=after_run,
            members=members,
            signing_key_id=str(delta_sig_summary.get("key_id", "")) or _key_id(public_key),
            claims_boundary=(
                "This handoff contains two independently verifiable customer evidence packs and a "
                "recomputable signed governance delta. The common Ed25519 key demonstrates local signer "
                "continuity, not externally validated organizational identity. Status changes do not prove "
                "causation without a controlled before/after experiment."
            ),
        )

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, "w") as zf:
            for member in members:
                data, _ = member_data[member.path]
                _zip_write(zf, member.path, data)
            manifest = (
                json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            _zip_write(zf, "comparison-manifest.json", manifest)

    pack_signature = Path(str(output) + ".ed25519.json")
    sign_file(output, private_key, pack_signature)
    pack_sig_ok, pack_sig_errors, _ = verify_signature(
        output,
        pack_signature,
        public_key_path=public_key,
    )
    if not pack_sig_ok:
        raise ValueError("comparison-pack signature failed: " + "; ".join(pack_sig_errors))
    return output, pack_signature, summary


def _extract_customer_evidence(pack: Path, target: Path) -> tuple[str, Path, bytes]:
    with zipfile.ZipFile(pack, "r") as zf:
        manifest = json.loads(zf.read("pack-manifest.json").decode("utf-8"))
        run_id = str(manifest.get("source_run_id", ""))
        if not run_id:
            raise ValueError("nested customer pack is missing source_run_id")
        public_key = zf.read("trust/attestation-public.json")
        prefix = f"evidence/{run_id}/"
        members = [name for name in zf.namelist() if name.startswith(prefix)]
        if not members:
            raise ValueError(f"nested customer pack has no evidence for {run_id}")
        evidence_root = target / "evidence" / run_id
        for name in members:
            relative = PurePosixPath(name).relative_to(PurePosixPath(prefix))
            destination = evidence_root / Path(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(zf.read(name))
        return run_id, evidence_root, public_key


def verify_comparison_pack(
    pack_path: str | Path,
    *,
    signature_path: str | Path | None = None,
    public_key_path: str | Path | None = None,
) -> tuple[bool, list[str], dict[str, Any]]:
    pack = Path(pack_path)
    errors: list[str] = []
    details: dict[str, Any] = {}
    try:
        with zipfile.ZipFile(pack, "r") as zf:
            names_list = zf.namelist()
            names = set(names_list)
            if len(names_list) != len(names):
                errors.append("comparison pack contains duplicate member names")
            for name in names_list:
                _validate_member(name)
            if "comparison-manifest.json" not in names:
                return False, ["comparison-manifest.json is missing"], {}
            manifest = json.loads(zf.read("comparison-manifest.json").decode("utf-8"))
            if manifest.get("schema_version") != 1:
                errors.append("unsupported comparison-pack schema_version")
            members = manifest.get("members", [])
            if not isinstance(members, list):
                errors.append("comparison manifest members must be a list")
                members = []
            expected_names = {"comparison-manifest.json"}
            for index, item in enumerate(members, start=1):
                if not isinstance(item, dict):
                    errors.append(f"comparison member {index}: malformed entry")
                    continue
                name = str(item.get("path", ""))
                _validate_member(name)
                expected_names.add(name)
                if name not in names:
                    errors.append(f"comparison member {index}: missing {name}")
                    continue
                data = zf.read(name)
                if _sha256_bytes(data) != str(item.get("sha256", "")):
                    errors.append(f"comparison member {index}: digest mismatch for {name}")
                if len(data) != int(item.get("size", -1)):
                    errors.append(f"comparison member {index}: size mismatch for {name}")
            unexpected = sorted(names - expected_names)
            if unexpected:
                errors.append("comparison pack has unmanifested members: " + ", ".join(unexpected))
            if any(name.endswith("attestation-private.json") for name in names):
                errors.append("comparison pack contains a forbidden private key")

            required = {
                "before/customer-evidence-pack.zip",
                "after/customer-evidence-pack.zip",
                "comparison/governance-delta.json",
                "comparison/governance-delta.json.ed25519.json",
                "trust/attestation-public.json",
            }
            missing_required = sorted(required - names)
            if missing_required:
                errors.append("comparison pack is missing required members: " + ", ".join(missing_required))

            if not missing_required:
                with tempfile.TemporaryDirectory(prefix="abl-comparison-verify-") as temp_dir:
                    temp = Path(temp_dir)
                    before_pack = temp / "before.zip"
                    after_pack = temp / "after.zip"
                    delta_json = temp / "governance-delta.json"
                    delta_signature = temp / "governance-delta.json.ed25519.json"
                    embedded_public = temp / "attestation-public.json"
                    before_pack.write_bytes(zf.read("before/customer-evidence-pack.zip"))
                    after_pack.write_bytes(zf.read("after/customer-evidence-pack.zip"))
                    delta_json.write_bytes(zf.read("comparison/governance-delta.json"))
                    delta_signature.write_bytes(
                        zf.read("comparison/governance-delta.json.ed25519.json")
                    )
                    embedded_public.write_bytes(zf.read("trust/attestation-public.json"))

                    before_ok, before_errors, before_summary = verify_pack(before_pack)
                    after_ok, after_errors, after_summary = verify_pack(after_pack)
                    if not before_ok:
                        errors.extend(f"before pack: {item}" for item in before_errors)
                    if not after_ok:
                        errors.extend(f"after pack: {item}" for item in after_errors)

                    before_run, before_evidence, before_key = _extract_customer_evidence(
                        before_pack,
                        temp / "before",
                    )
                    after_run, after_evidence, after_key = _extract_customer_evidence(
                        after_pack,
                        temp / "after",
                    )
                    top_key = embedded_public.read_bytes()
                    if before_key != top_key or after_key != top_key:
                        errors.append(
                            "before/after packs do not use the comparison pack public verification key"
                        )

                    delta_ok, delta_errors, delta_summary = verify_delta(
                        delta_json,
                        before_evidence,
                        after_evidence,
                    )
                    if not delta_ok:
                        errors.extend(f"governance delta: {item}" for item in delta_errors)
                    delta_sig_ok, delta_sig_errors, delta_sig_summary = verify_signature(
                        delta_json,
                        delta_signature,
                        public_key_path=embedded_public,
                    )
                    if not delta_sig_ok:
                        errors.extend(f"delta signature: {item}" for item in delta_sig_errors)

                    if str(manifest.get("before_run_id", "")) != before_run:
                        errors.append("comparison manifest before_run_id mismatch")
                    if str(manifest.get("after_run_id", "")) != after_run:
                        errors.append("comparison manifest after_run_id mismatch")
                    if str(manifest.get("signing_key_id", "")) != str(
                        delta_sig_summary.get("key_id", "")
                    ):
                        errors.append("comparison manifest signing_key_id mismatch")

                    details.update(
                        {
                            "before": before_summary,
                            "after": after_summary,
                            "delta": delta_summary,
                            "delta_signature": delta_sig_summary,
                        }
                    )

        external_signature_checked = signature_path is not None or public_key_path is not None
        if external_signature_checked:
            if signature_path is None or public_key_path is None:
                errors.append(
                    "both signature_path and public_key_path are required for external pack verification"
                )
            else:
                pack_sig_ok, pack_sig_errors, pack_sig_summary = verify_signature(
                    pack,
                    signature_path,
                    public_key_path=public_key_path,
                )
                if not pack_sig_ok:
                    errors.extend(f"comparison pack signature: {item}" for item in pack_sig_errors)
                details["pack_signature"] = pack_sig_summary

        details.update(
            {
                "comparison_pack_sha256": sha256_file(pack),
                "external_pack_signature_checked": external_signature_checked,
                "valid": not errors,
            }
        )
    except (OSError, ValueError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        return False, [f"comparison pack cannot be verified: {exc}"], {}
    return not errors, errors, details


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create or verify an offline before/after governance comparison handoff"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create")
    create.add_argument("before")
    create.add_argument("after")
    create.add_argument("--root", default=".")
    create.add_argument("--output", required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("pack")
    verify.add_argument("--signature", default=None)
    verify.add_argument("--public", default=None)

    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            pack, signature, summary = create_comparison_pack(
                args.root,
                args.before,
                args.after,
                output_path=args.output,
            )
            print(
                json.dumps(
                    {
                        **summary.to_dict(),
                        "pack": str(pack),
                        "pack_sha256": sha256_file(pack),
                        "signature": str(signature),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        ok, errors, summary = verify_comparison_pack(
            args.pack,
            signature_path=args.signature,
            public_key_path=args.public,
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        for error in errors:
            print(f"ERROR: {error}")
        return 0 if ok else 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
