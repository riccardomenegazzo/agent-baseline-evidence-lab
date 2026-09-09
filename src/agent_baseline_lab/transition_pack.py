from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .artifact_diff import create_artifact_diff, verify_artifact_diff
from .comparison_pack import create_comparison_pack, verify_comparison_pack
from .evidence import sha256_file
from .signing import sign_file, verify_signature

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class TransitionMember:
    path: str
    role: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TransitionPackSummary:
    schema_version: int
    before_run_id: str
    after_run_id: str
    artifact_classification: str
    members: list[TransitionMember]
    signing_key_id: str
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "before_run_id": self.before_run_id,
            "after_run_id": self.after_run_id,
            "artifact_classification": self.artifact_classification,
            "members": [item.to_dict() for item in self.members],
            "signing_key_id": self.signing_key_id,
            "claims_boundary": self.claims_boundary,
        }


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_member(name: str) -> str:
    pure = PurePosixPath(name)
    if not name or pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe transition-pack member path: {name}")
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
            "transition pack requires an Ed25519 keypair; run `make signing-keygen` first. "
            "Missing: " + ", ".join(missing)
        )
    return private_key, public_key


def _key_id(public_key: Path) -> str:
    try:
        payload = json.loads(public_key.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid public verification key: {exc}") from exc
    key_id = str(payload.get("key_id", "")).strip() if isinstance(payload, dict) else ""
    if not key_id:
        raise ValueError("public verification key is missing key_id")
    return key_id


def _resolve(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _load_object(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def _nested_public_key(pack: Path) -> bytes:
    with zipfile.ZipFile(pack, "r") as zf:
        return zf.read("trust/attestation-public.json")


def create_transition_pack(
    root_path: str | Path,
    before_evidence: str | Path,
    after_evidence: str | Path,
    before_trusted_artifact: str | Path,
    after_trusted_artifact: str | Path,
    *,
    output_path: str | Path,
) -> tuple[Path, Path, TransitionPackSummary]:
    root = Path(root_path).resolve()
    private_key, public_key = _required_keypair(root)
    before_report = _resolve(root, before_trusted_artifact)
    after_report = _resolve(root, after_trusted_artifact)
    if not before_report.is_file() or not after_report.is_file():
        raise ValueError("transition pack requires both trusted-artifact reports")

    with tempfile.TemporaryDirectory(prefix="abl-transition-create-") as temp_dir:
        temp = Path(temp_dir)

        comparison_pack = temp / "governance-comparison.zip"
        comparison_pack_path, comparison_signature, comparison_summary = create_comparison_pack(
            root,
            before_evidence,
            after_evidence,
            output_path=comparison_pack,
        )
        comparison_ok, comparison_errors, _ = verify_comparison_pack(
            comparison_pack_path,
            signature_path=comparison_signature,
            public_key_path=public_key,
        )
        if not comparison_ok:
            raise ValueError(
                "governance comparison pack failed verification: " + "; ".join(comparison_errors)
            )
        if _nested_public_key(comparison_pack_path) != public_key.read_bytes():
            raise ValueError("governance comparison pack uses a different embedded public key")

        artifact_diff = temp / "oci-artifact-diff.json"
        artifact_diff_html = temp / "oci-artifact-diff.html"
        diff = create_artifact_diff(
            before_report,
            after_report,
            root_path=root,
            output=artifact_diff,
            html_output=artifact_diff_html,
        )
        diff_ok, diff_errors, _ = verify_artifact_diff(
            artifact_diff,
            before_report,
            after_report,
            root_path=root,
        )
        if not diff_ok:
            raise ValueError("OCI artifact diff failed verification: " + "; ".join(diff_errors))
        artifact_diff_signature = temp / "oci-artifact-diff.json.ed25519.json"
        sign_file(artifact_diff, private_key, artifact_diff_signature)
        diff_sig_ok, diff_sig_errors, _ = verify_signature(
            artifact_diff,
            artifact_diff_signature,
            public_key_path=public_key,
        )
        if not diff_sig_ok:
            raise ValueError("OCI artifact diff signature failed: " + "; ".join(diff_sig_errors))

        before_report_bytes = before_report.read_bytes()
        after_report_bytes = after_report.read_bytes()
        if _sha256_bytes(before_report_bytes) != diff.before.report_sha256:
            raise ValueError("before trusted-artifact report does not match artifact diff snapshot")
        if _sha256_bytes(after_report_bytes) != diff.after.report_sha256:
            raise ValueError("after trusted-artifact report does not match artifact diff snapshot")

        member_data: dict[str, tuple[bytes, str]] = {
            "governance/comparison-pack.zip": (
                comparison_pack_path.read_bytes(),
                "governance-comparison-pack",
            ),
            "governance/comparison-pack.zip.ed25519.json": (
                comparison_signature.read_bytes(),
                "governance-comparison-pack-signature",
            ),
            "artifact/oci-artifact-diff.json": (
                artifact_diff.read_bytes(),
                "oci-artifact-diff",
            ),
            "artifact/oci-artifact-diff.html": (
                artifact_diff_html.read_bytes(),
                "oci-artifact-diff-html",
            ),
            "artifact/oci-artifact-diff.json.ed25519.json": (
                artifact_diff_signature.read_bytes(),
                "oci-artifact-diff-signature",
            ),
            "artifact/before-trusted-artifact.json": (
                before_report_bytes,
                "before-trusted-artifact",
            ),
            "artifact/after-trusted-artifact.json": (
                after_report_bytes,
                "after-trusted-artifact",
            ),
            "trust/attestation-public.json": (
                public_key.read_bytes(),
                "public-verification-key",
            ),
        }
        members = [
            TransitionMember(
                path=name,
                role=role,
                sha256=_sha256_bytes(data),
                size=len(data),
            )
            for name, (data, role) in sorted(member_data.items())
        ]
        summary = TransitionPackSummary(
            schema_version=SCHEMA_VERSION,
            before_run_id=comparison_summary.before_run_id,
            after_run_id=comparison_summary.after_run_id,
            artifact_classification=diff.classification,
            members=members,
            signing_key_id=_key_id(public_key),
            claims_boundary=(
                "This transition handoff combines two distinct evidence planes: a recomputable governance "
                "comparison and a verified OCI artifact diff. Their co-location does not prove that a governance "
                "change caused an artifact change, or vice versa. Portable verification proves pack integrity, "
                "signature continuity and binding of the embedded trusted-artifact reports to the signed diff. "
                "Full OCI recomputation additionally requires the original before/after OCI archives referenced "
                "by those reports. Signer continuity is local key continuity, not externally validated identity."
            ),
        )

        output = _resolve(root, output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, "w") as zf:
            for member in members:
                data, _ = member_data[member.path]
                _zip_write(zf, member.path, data)
            manifest = (
                json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            _zip_write(zf, "transition-manifest.json", manifest)

    pack_signature = Path(str(output) + ".ed25519.json")
    sign_file(output, private_key, pack_signature)
    pack_sig_ok, pack_sig_errors, _ = verify_signature(
        output,
        pack_signature,
        public_key_path=public_key,
    )
    if not pack_sig_ok:
        raise ValueError("transition-pack signature failed: " + "; ".join(pack_sig_errors))
    return output, pack_signature, summary


def verify_transition_pack(
    pack_path: str | Path,
    *,
    signature_path: str | Path | None = None,
    public_key_path: str | Path | None = None,
    before_trusted_artifact: str | Path | None = None,
    after_trusted_artifact: str | Path | None = None,
    root_path: str | Path = ".",
) -> tuple[bool, list[str], dict[str, Any]]:
    pack = Path(pack_path)
    root = Path(root_path).resolve()
    errors: list[str] = []
    details: dict[str, Any] = {}
    embedded_public_bytes = b""
    full_recompute_requested = (
        before_trusted_artifact is not None or after_trusted_artifact is not None
    )
    if full_recompute_requested and (
        before_trusted_artifact is None or after_trusted_artifact is None
    ):
        return False, [
            "both before_trusted_artifact and after_trusted_artifact are required for full OCI recomputation"
        ], {"artifact_recomputed": False, "valid": False}

    try:
        with zipfile.ZipFile(pack, "r") as zf:
            names_list = zf.namelist()
            names = set(names_list)
            if len(names_list) != len(names):
                errors.append("transition pack contains duplicate member names")
            for name in names_list:
                _validate_member(name)
            if "transition-manifest.json" not in names:
                return False, ["transition-manifest.json is missing"], {}

            manifest = _load_object(
                zf.read("transition-manifest.json"),
                label="transition manifest",
            )
            if manifest.get("schema_version") != SCHEMA_VERSION:
                errors.append("unsupported transition-pack schema_version")

            members = manifest.get("members", [])
            if not isinstance(members, list):
                errors.append("transition manifest members must be a list")
                members = []
            expected_names = {"transition-manifest.json"}
            seen_manifest_paths: set[str] = set()
            for index, item in enumerate(members, start=1):
                if not isinstance(item, dict):
                    errors.append(f"transition member {index}: malformed entry")
                    continue
                name = str(item.get("path", ""))
                _validate_member(name)
                if name in seen_manifest_paths:
                    errors.append(f"transition manifest contains duplicate member path: {name}")
                    continue
                seen_manifest_paths.add(name)
                expected_names.add(name)
                if name not in names:
                    errors.append(f"transition member {index}: missing {name}")
                    continue
                data = zf.read(name)
                if _sha256_bytes(data) != str(item.get("sha256", "")):
                    errors.append(f"transition member {index}: digest mismatch for {name}")
                if len(data) != int(item.get("size", -1)):
                    errors.append(f"transition member {index}: size mismatch for {name}")

            unexpected = sorted(names - expected_names)
            if unexpected:
                errors.append("transition pack has unmanifested members: " + ", ".join(unexpected))
            if any(name.endswith("attestation-private.json") for name in names):
                errors.append("transition pack contains a forbidden private key")

            required = {
                "governance/comparison-pack.zip",
                "governance/comparison-pack.zip.ed25519.json",
                "artifact/oci-artifact-diff.json",
                "artifact/oci-artifact-diff.json.ed25519.json",
                "artifact/before-trusted-artifact.json",
                "artifact/after-trusted-artifact.json",
                "trust/attestation-public.json",
            }
            missing_required = sorted(required - names)
            if missing_required:
                errors.append(
                    "transition pack is missing required members: " + ", ".join(missing_required)
                )

            if not missing_required:
                with tempfile.TemporaryDirectory(prefix="abl-transition-verify-") as temp_dir:
                    temp = Path(temp_dir)
                    comparison_pack = temp / "governance-comparison.zip"
                    comparison_signature = temp / "governance-comparison.zip.ed25519.json"
                    artifact_diff = temp / "oci-artifact-diff.json"
                    artifact_diff_signature = temp / "oci-artifact-diff.json.ed25519.json"
                    embedded_public = temp / "attestation-public.json"
                    embedded_before = temp / "before-trusted-artifact.json"
                    embedded_after = temp / "after-trusted-artifact.json"

                    comparison_pack.write_bytes(zf.read("governance/comparison-pack.zip"))
                    comparison_signature.write_bytes(
                        zf.read("governance/comparison-pack.zip.ed25519.json")
                    )
                    artifact_diff.write_bytes(zf.read("artifact/oci-artifact-diff.json"))
                    artifact_diff_signature.write_bytes(
                        zf.read("artifact/oci-artifact-diff.json.ed25519.json")
                    )
                    embedded_public_bytes = zf.read("trust/attestation-public.json")
                    embedded_public.write_bytes(embedded_public_bytes)
                    embedded_before.write_bytes(
                        zf.read("artifact/before-trusted-artifact.json")
                    )
                    embedded_after.write_bytes(
                        zf.read("artifact/after-trusted-artifact.json")
                    )

                    comparison_ok, comparison_errors, comparison_details = verify_comparison_pack(
                        comparison_pack,
                        signature_path=comparison_signature,
                        public_key_path=embedded_public,
                    )
                    if not comparison_ok:
                        errors.extend(
                            f"governance comparison: {item}" for item in comparison_errors
                        )
                    try:
                        if _nested_public_key(comparison_pack) != embedded_public.read_bytes():
                            errors.append(
                                "governance comparison pack public key does not match transition public key"
                            )
                    except (KeyError, zipfile.BadZipFile):
                        errors.append("governance comparison pack public key cannot be inspected")

                    diff_sig_ok, diff_sig_errors, diff_sig_details = verify_signature(
                        artifact_diff,
                        artifact_diff_signature,
                        public_key_path=embedded_public,
                    )
                    if not diff_sig_ok:
                        errors.extend(f"artifact diff signature: {item}" for item in diff_sig_errors)

                    diff_payload = _load_object(
                        artifact_diff.read_bytes(),
                        label="OCI artifact diff",
                    )
                    before_snapshot = diff_payload.get("before", {})
                    after_snapshot = diff_payload.get("after", {})
                    if not isinstance(before_snapshot, dict) or not isinstance(after_snapshot, dict):
                        errors.append("OCI artifact diff snapshots are malformed")
                        before_snapshot = {}
                        after_snapshot = {}
                    before_bound = (
                        _sha256_bytes(embedded_before.read_bytes())
                        == str(before_snapshot.get("report_sha256", ""))
                    )
                    after_bound = (
                        _sha256_bytes(embedded_after.read_bytes())
                        == str(after_snapshot.get("report_sha256", ""))
                    )
                    if not before_bound:
                        errors.append(
                            "embedded before trusted-artifact report does not match signed artifact diff"
                        )
                    if not after_bound:
                        errors.append(
                            "embedded after trusted-artifact report does not match signed artifact diff"
                        )

                    with zipfile.ZipFile(comparison_pack, "r") as comparison_zip:
                        nested_manifest = _load_object(
                            comparison_zip.read("comparison-manifest.json"),
                            label="comparison manifest",
                        )
                    if str(manifest.get("before_run_id", "")) != str(
                        nested_manifest.get("before_run_id", "")
                    ):
                        errors.append("transition manifest before_run_id mismatch")
                    if str(manifest.get("after_run_id", "")) != str(
                        nested_manifest.get("after_run_id", "")
                    ):
                        errors.append("transition manifest after_run_id mismatch")
                    if str(manifest.get("artifact_classification", "")) != str(
                        diff_payload.get("classification", "")
                    ):
                        errors.append("transition manifest artifact_classification mismatch")

                    public_payload = _load_object(
                        embedded_public.read_bytes(),
                        label="public verification key",
                    )
                    if str(manifest.get("signing_key_id", "")) != str(
                        public_payload.get("key_id", "")
                    ):
                        errors.append("transition manifest signing_key_id mismatch")

                    artifact_recomputed = False
                    artifact_recompute_details: dict[str, Any] = {}
                    if full_recompute_requested:
                        assert before_trusted_artifact is not None
                        assert after_trusted_artifact is not None
                        before_source = _resolve(root, before_trusted_artifact)
                        after_source = _resolve(root, after_trusted_artifact)
                        if sha256_file(before_source) != _sha256_bytes(embedded_before.read_bytes()):
                            errors.append(
                                "provided before trusted-artifact report differs from embedded report"
                            )
                        if sha256_file(after_source) != _sha256_bytes(embedded_after.read_bytes()):
                            errors.append(
                                "provided after trusted-artifact report differs from embedded report"
                            )
                        if not errors:
                            recompute_ok, recompute_errors, recomputed = verify_artifact_diff(
                                artifact_diff,
                                before_source,
                                after_source,
                                root_path=root,
                            )
                            artifact_recomputed = recompute_ok
                            artifact_recompute_details = {
                                "classification": recomputed.classification,
                                "errors": recompute_errors,
                            }
                            if not recompute_ok:
                                errors.extend(
                                    f"artifact recomputation: {item}"
                                    for item in recompute_errors
                                )

                    details.update(
                        {
                            "governance_comparison": comparison_details,
                            "artifact_diff_signature": diff_sig_details,
                            "artifact_classification": diff_payload.get("classification", ""),
                            "source_report_bindings": {
                                "before": before_bound,
                                "after": after_bound,
                            },
                            "artifact_recomputed": artifact_recomputed,
                            "artifact_recomputation": artifact_recompute_details,
                        }
                    )

        external_signature_checked = signature_path is not None or public_key_path is not None
        if external_signature_checked:
            if signature_path is None or public_key_path is None:
                errors.append(
                    "both signature_path and public_key_path are required for external pack verification"
                )
            else:
                external_public = Path(public_key_path)
                if embedded_public_bytes and external_public.read_bytes() != embedded_public_bytes:
                    errors.append("external public key does not match transition embedded public key")
                pack_sig_ok, pack_sig_errors, pack_sig_details = verify_signature(
                    pack,
                    signature_path,
                    public_key_path=public_key_path,
                )
                if not pack_sig_ok:
                    errors.extend(f"transition pack signature: {item}" for item in pack_sig_errors)
                details["pack_signature"] = pack_sig_details

        details.update(
            {
                "transition_pack_sha256": sha256_file(pack),
                "external_pack_signature_checked": external_signature_checked,
                "full_artifact_recomputation_requested": full_recompute_requested,
                "valid": not errors,
            }
        )
    except (
        OSError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        zipfile.BadZipFile,
    ) as exc:
        return False, [f"transition pack cannot be verified: {exc}"], {}
    return not errors, errors, details


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create or verify a signed remediation transition handoff"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create")
    create.add_argument("before_evidence")
    create.add_argument("after_evidence")
    create.add_argument("before_trusted_artifact")
    create.add_argument("after_trusted_artifact")
    create.add_argument("--root", default=".")
    create.add_argument("--output", required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("pack")
    verify.add_argument("--signature", default=None)
    verify.add_argument("--public", default=None)
    verify.add_argument("--before-trusted-artifact", default=None)
    verify.add_argument("--after-trusted-artifact", default=None)
    verify.add_argument("--root", default=".")

    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            pack, signature, summary = create_transition_pack(
                args.root,
                args.before_evidence,
                args.after_evidence,
                args.before_trusted_artifact,
                args.after_trusted_artifact,
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

        ok, errors, summary = verify_transition_pack(
            args.pack,
            signature_path=args.signature,
            public_key_path=args.public,
            before_trusted_artifact=args.before_trusted_artifact,
            after_trusted_artifact=args.after_trusted_artifact,
            root_path=args.root,
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
