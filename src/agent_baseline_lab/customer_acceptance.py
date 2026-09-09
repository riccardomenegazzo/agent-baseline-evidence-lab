from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .customer_policy import (
    evaluate_policy,
    load_policy_profile,
    policy_source_bytes,
    verify_policy_evaluation,
)
from .evidence import sha256_file
from .signing import sign_file, verify_signature
from .trust_handoff import verify_handoff_pack


@dataclass(frozen=True)
class AcceptanceFile:
    path: str
    role: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AcceptanceSummary:
    schema_version: int
    generated_at: str
    source_run_id: str
    profile_id: str
    profile_version: str
    profile_sha256: str
    policy_status: str
    handoff_sha256: str
    trusted_artifact_sha256: str
    files: list[AcceptanceFile]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["files"] = [item.to_dict() for item in self.files]
        if self.schema_version == 1:
            payload.pop("trusted_artifact_sha256", None)
        return payload


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_archive_path(value: str) -> str:
    pure = PurePosixPath(value)
    if not value or pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe acceptance archive path: {value}")
    return pure.as_posix()


def _zip_write(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    zf.writestr(info, data)


def _role_map(manifest: dict[str, Any]) -> dict[str, str]:
    roles: dict[str, str] = {}
    files = manifest.get("files", [])
    if not isinstance(files, list):
        raise ValueError("manifest files must be an array")
    for item in files:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role", ""))
        path = str(item.get("path", ""))
        if not role or not path:
            continue
        if role in roles:
            raise ValueError(f"duplicate manifest role: {role}")
        roles[role] = _safe_archive_path(path)
    return roles


def _handoff_evidence(handoff: Path) -> tuple[bytes, bytes | None, str]:
    with zipfile.ZipFile(handoff, "r") as zf:
        manifest = json.loads(zf.read("handoff-manifest.json").decode("utf-8"))
        roles = _role_map(manifest)
        decision_member = roles.get("customer-decision")
        if not decision_member:
            raise ValueError("customer trust handoff does not contain a customer-decision role")
        artifact_member = roles.get("trusted-artifact")
        artifact_bytes = zf.read(artifact_member) if artifact_member else None
        return (
            zf.read(decision_member),
            artifact_bytes,
            str(manifest.get("source_run_id", "")),
        )


def _decode_json_object(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} in handoff is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} in handoff must be a JSON object")
    return payload


def _materialize_policy_evaluation(
    policy_source: str | Path,
    decision_bytes: bytes,
    trusted_artifact_bytes: bytes | None,
    destination: Path,
) -> tuple[dict[str, Any], str]:
    profile, profile_sha256 = load_policy_profile(policy_source)
    decision = _decode_json_object(decision_bytes, label="customer decision")
    trusted_artifact = (
        _decode_json_object(trusted_artifact_bytes, label="trusted artifact")
        if trusted_artifact_bytes is not None
        else None
    )
    artifact_sha256 = (
        _sha256_bytes(trusted_artifact_bytes) if trusted_artifact_bytes is not None else ""
    )
    evaluation = evaluate_policy(
        profile,
        decision,
        profile_sha256=profile_sha256,
        trusted_artifact=trusted_artifact,
        trusted_artifact_sha256=artifact_sha256,
        evaluation_schema_version=2,
    )
    destination.write_text(
        json.dumps(evaluation.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return evaluation.to_dict(), profile_sha256


def create_acceptance_pack(
    handoff_path: str | Path,
    *,
    handoff_signature_path: str | Path,
    public_key_path: str | Path,
    private_key_path: str | Path,
    policy_path: str | Path,
    output_path: str | Path,
) -> tuple[Path, Path, AcceptanceSummary]:
    handoff = Path(handoff_path)
    handoff_signature = Path(handoff_signature_path)
    public_key = Path(public_key_path)
    private_key = Path(private_key_path)
    policy_source = policy_path
    for label, path in (
        ("handoff", handoff),
        ("handoff signature", handoff_signature),
        ("public key", public_key),
        ("private key", private_key),
    ):
        if not path.is_file():
            raise ValueError(f"{label} does not exist: {path}")
    policy_bytes = policy_source_bytes(policy_source)

    handoff_ok, handoff_errors, handoff_details = verify_handoff_pack(handoff)
    if not handoff_ok:
        raise ValueError("refusing invalid customer trust handoff: " + "; ".join(handoff_errors))
    signature_ok, signature_errors, _ = verify_signature(
        handoff,
        handoff_signature,
        public_key_path=public_key,
    )
    if not signature_ok:
        raise ValueError("handoff signature verification failed: " + "; ".join(signature_errors))

    decision_bytes, trusted_artifact_bytes, source_run_id = _handoff_evidence(handoff)
    if not source_run_id:
        source_run_id = str(handoff_details.get("source_run_id", ""))
    if not source_run_id:
        raise ValueError("customer trust handoff does not identify its source run")
    trusted_artifact_sha256 = (
        _sha256_bytes(trusted_artifact_bytes) if trusted_artifact_bytes is not None else ""
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="abl-accept-") as tmp:
        tmp_root = Path(tmp)
        evaluation = tmp_root / "customer-policy-evaluation.json"
        evaluation_payload, profile_sha256 = _materialize_policy_evaluation(
            policy_source,
            decision_bytes,
            trusted_artifact_bytes,
            evaluation,
        )
        if str(evaluation_payload.get("status", "")) != "PASS":
            failed = [
                str(item.get("requirement", "unknown"))
                for item in evaluation_payload.get("checks", [])
                if isinstance(item, dict) and item.get("status") == "FAIL"
            ]
            raise ValueError(
                "customer policy is not satisfied; failing requirement(s): "
                + ", ".join(failed or ["unknown"])
            )

        evaluation_signature = tmp_root / "customer-policy-evaluation.ed25519.json"
        sign_file(evaluation, private_key, evaluation_signature)
        evaluation_sig_ok, evaluation_sig_errors, _ = verify_signature(
            evaluation,
            evaluation_signature,
            public_key_path=public_key,
        )
        if not evaluation_sig_ok:
            raise ValueError(
                "policy evaluation signature verification failed: "
                + "; ".join(evaluation_sig_errors)
            )

        statement_payload = {
            "schema_version": 2,
            "generated_at": _utc_now(),
            "source_run_id": source_run_id,
            "handoff_sha256": sha256_file(handoff),
            "handoff_signature_sha256": sha256_file(handoff_signature),
            "decision_sha256": _sha256_bytes(decision_bytes),
            "trusted_artifact_sha256": trusted_artifact_sha256,
            "profile_id": str(evaluation_payload.get("profile_id", "")),
            "profile_version": str(evaluation_payload.get("profile_version", "")),
            "profile_sha256": profile_sha256,
            "policy_status": "PASS",
            "policy_evaluation_sha256": sha256_file(evaluation),
            "claims_boundary": (
                "This statement binds one verified customer trust handoff, its customer decision, "
                "the nested trusted-artifact evidence when present, one exact customer acceptance "
                "policy and its recomputable PASS evaluation. It does not alter the underlying "
                "evidence, prove external signer identity, authorize production, or constitute "
                "Docker/compliance certification."
            ),
        }
        statement = tmp_root / "acceptance-statement.json"
        statement.write_text(
            json.dumps(statement_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        statement_signature = tmp_root / "acceptance-statement.ed25519.json"
        sign_file(statement, private_key, statement_signature)
        statement_sig_ok, statement_sig_errors, _ = verify_signature(
            statement,
            statement_signature,
            public_key_path=public_key,
        )
        if not statement_sig_ok:
            raise ValueError(
                "acceptance statement signature verification failed: "
                + "; ".join(statement_sig_errors)
            )

        raw_entries: list[tuple[str, str, bytes]] = [
            ("customer-trust-handoff", "evidence/customer-trust-handoff.zip", handoff.read_bytes()),
            (
                "customer-trust-handoff-signature",
                "evidence/customer-trust-handoff.zip.ed25519.json",
                handoff_signature.read_bytes(),
            ),
            ("public-verification-key", "trust/attestation-public.json", public_key.read_bytes()),
            ("customer-policy-profile", "policy/customer-policy.yaml", policy_bytes),
            (
                "customer-policy-evaluation",
                "policy/customer-policy-evaluation.json",
                evaluation.read_bytes(),
            ),
            (
                "customer-policy-evaluation-signature",
                "policy/customer-policy-evaluation.ed25519.json",
                evaluation_signature.read_bytes(),
            ),
            ("acceptance-statement", "acceptance/acceptance-statement.json", statement.read_bytes()),
            (
                "acceptance-statement-signature",
                "acceptance/acceptance-statement.ed25519.json",
                statement_signature.read_bytes(),
            ),
        ]
        files = [
            AcceptanceFile(
                path=archive,
                role=role,
                sha256=_sha256_bytes(data),
                size=len(data),
            )
            for role, archive, data in raw_entries
        ]
        summary = AcceptanceSummary(
            schema_version=2,
            generated_at=str(statement_payload["generated_at"]),
            source_run_id=source_run_id,
            profile_id=str(evaluation_payload["profile_id"]),
            profile_version=str(evaluation_payload["profile_version"]),
            profile_sha256=profile_sha256,
            policy_status="PASS",
            handoff_sha256=sha256_file(handoff),
            trusted_artifact_sha256=trusted_artifact_sha256,
            files=files,
            claims_boundary=(
                "The acceptance envelope is customer-policy-specific. Its PASS status means only "
                "that the included verified evidence handoff satisfies the exact included policy. "
                "Artifact-aware profiles are evaluated directly against the trusted-artifact JSON "
                "nested in that handoff. This is not a security score, production authorization, "
                "or certification."
            ),
        )
        with zipfile.ZipFile(output, "w") as zf:
            for _, archive, data in sorted(raw_entries, key=lambda item: item[1]):
                _zip_write(zf, archive, data)
            manifest = (
                json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            _zip_write(zf, "acceptance-manifest.json", manifest)

    pack_signature = output.with_name(output.name + ".ed25519.json")
    sign_file(output, private_key, pack_signature)
    ok, errors, _ = verify_acceptance_pack(output, signature_path=pack_signature)
    if not ok:
        raise ValueError("created acceptance envelope failed verification: " + "; ".join(errors))
    return output, pack_signature, summary


def verify_acceptance_pack(
    path: str | Path,
    *,
    signature_path: str | Path | None = None,
) -> tuple[bool, list[str], dict[str, Any]]:
    pack = Path(path)
    errors: list[str] = []
    details: dict[str, Any] = {}
    if not pack.is_file():
        return False, [f"acceptance envelope does not exist: {pack}"], details

    try:
        with zipfile.ZipFile(pack, "r") as zf:
            names_list = zf.namelist()
            names = set(names_list)
            if len(names_list) != len(names):
                errors.append("acceptance ZIP contains duplicate member names")
            for name in names_list:
                _safe_archive_path(name)
            if "acceptance-manifest.json" not in names:
                return False, ["acceptance-manifest.json is missing"], details
            manifest = json.loads(zf.read("acceptance-manifest.json").decode("utf-8"))
            manifest_schema = manifest.get("schema_version")
            if manifest_schema not in {1, 2}:
                errors.append("unsupported acceptance schema_version")
            roles = _role_map(manifest)
            expected = {"acceptance-manifest.json"}
            verified_files = 0
            for index, item in enumerate(manifest.get("files", []), start=1):
                if not isinstance(item, dict):
                    errors.append(f"acceptance file {index}: malformed manifest entry")
                    continue
                member = _safe_archive_path(str(item.get("path", "")))
                expected.add(member)
                if member not in names:
                    errors.append(f"acceptance file {index}: missing member {member}")
                    continue
                data = zf.read(member)
                if _sha256_bytes(data) != str(item.get("sha256", "")):
                    errors.append(f"acceptance file {index}: digest mismatch for {member}")
                    continue
                if len(data) != int(item.get("size", -1)):
                    errors.append(f"acceptance file {index}: size mismatch for {member}")
                    continue
                verified_files += 1
            unexpected = sorted(names - expected)
            if unexpected:
                errors.append("acceptance ZIP contains unmanifested members: " + ", ".join(unexpected))

            required_roles = {
                "customer-trust-handoff",
                "customer-trust-handoff-signature",
                "public-verification-key",
                "customer-policy-profile",
                "customer-policy-evaluation",
                "customer-policy-evaluation-signature",
                "acceptance-statement",
                "acceptance-statement-signature",
            }
            missing_roles = sorted(required_roles - set(roles))
            if missing_roles:
                errors.append("acceptance envelope missing role(s): " + ", ".join(missing_roles))

            details["schema_version"] = manifest_schema
            details["verified_files"] = verified_files
            details["source_run_id"] = str(manifest.get("source_run_id", ""))
            details["profile_id"] = str(manifest.get("profile_id", ""))
            details["profile_version"] = str(manifest.get("profile_version", ""))
            details["profile_sha256"] = str(manifest.get("profile_sha256", ""))
            details["policy_status"] = str(manifest.get("policy_status", ""))
            details["trusted_artifact_sha256"] = str(
                manifest.get("trusted_artifact_sha256", "")
            )

            if not missing_roles and manifest_schema in {1, 2}:
                with tempfile.TemporaryDirectory(prefix="abl-accept-verify-") as tmp:
                    tmp_root = Path(tmp)
                    extracted: dict[str, Path] = {}
                    for role in required_roles:
                        member = roles[role]
                        target = tmp_root / Path(member).name
                        target.write_bytes(zf.read(member))
                        extracted[role] = target

                    handoff = extracted["customer-trust-handoff"]
                    handoff_ok, handoff_errors, _ = verify_handoff_pack(handoff)
                    if not handoff_ok:
                        errors.extend(f"nested handoff: {error}" for error in handoff_errors)
                    details["nested_handoff_verified"] = handoff_ok

                    public_key = extracted["public-verification-key"]
                    handoff_sig_ok, handoff_sig_errors, _ = verify_signature(
                        handoff,
                        extracted["customer-trust-handoff-signature"],
                        public_key_path=public_key,
                    )
                    if not handoff_sig_ok:
                        errors.extend(
                            f"nested handoff signature: {error}" for error in handoff_sig_errors
                        )
                    details["nested_handoff_signature_verified"] = handoff_sig_ok

                    decision_bytes, trusted_artifact_bytes, source_run_id = _handoff_evidence(handoff)
                    decision = tmp_root / "customer-decision.json"
                    decision.write_bytes(decision_bytes)
                    trusted_artifact_path: Path | None = None
                    trusted_artifact_sha256 = ""
                    if trusted_artifact_bytes is not None:
                        trusted_artifact_path = tmp_root / "trusted-artifact.json"
                        trusted_artifact_path.write_bytes(trusted_artifact_bytes)
                        trusted_artifact_sha256 = _sha256_bytes(trusted_artifact_bytes)

                    policy_ok, policy_errors, recomputed = verify_policy_evaluation(
                        extracted["customer-policy-evaluation"],
                        extracted["customer-policy-profile"],
                        decision,
                        trusted_artifact_path=trusted_artifact_path,
                    )
                    if not policy_ok:
                        errors.extend(f"customer policy: {error}" for error in policy_errors)
                    if recomputed.status != "PASS":
                        errors.append("customer policy recomputes to non-PASS status")
                    details["policy_evaluation_verified"] = policy_ok
                    details["policy_recomputed_status"] = recomputed.status
                    details["nested_trusted_artifact_sha256"] = trusted_artifact_sha256

                    evaluation_sig_ok, evaluation_sig_errors, _ = verify_signature(
                        extracted["customer-policy-evaluation"],
                        extracted["customer-policy-evaluation-signature"],
                        public_key_path=public_key,
                    )
                    if not evaluation_sig_ok:
                        errors.extend(
                            f"policy evaluation signature: {error}"
                            for error in evaluation_sig_errors
                        )
                    details["policy_evaluation_signature_verified"] = evaluation_sig_ok

                    statement = json.loads(
                        extracted["acceptance-statement"].read_text(encoding="utf-8")
                    )
                    if not isinstance(statement, dict):
                        raise ValueError("acceptance statement must be a JSON object")
                    statement_schema = statement.get("schema_version")
                    if statement_schema not in {1, 2}:
                        errors.append("unsupported acceptance statement schema_version")
                    if manifest_schema == 2 and statement_schema != 2:
                        errors.append("acceptance schema v2 requires acceptance statement schema v2")

                    profile, profile_sha256 = load_policy_profile(
                        extracted["customer-policy-profile"]
                    )
                    expected_statement: dict[str, Any] = {
                        "source_run_id": source_run_id,
                        "handoff_sha256": sha256_file(handoff),
                        "handoff_signature_sha256": sha256_file(
                            extracted["customer-trust-handoff-signature"]
                        ),
                        "decision_sha256": _sha256_bytes(decision_bytes),
                        "profile_id": str(profile["id"]),
                        "profile_version": str(profile["version"]),
                        "profile_sha256": profile_sha256,
                        "policy_status": "PASS",
                        "policy_evaluation_sha256": sha256_file(
                            extracted["customer-policy-evaluation"]
                        ),
                    }
                    if statement_schema == 2:
                        expected_statement["trusted_artifact_sha256"] = trusted_artifact_sha256
                    for field, expected_value in expected_statement.items():
                        if statement.get(field) != expected_value:
                            errors.append(f"acceptance statement mismatch: {field}")

                    statement_sig_ok, statement_sig_errors, _ = verify_signature(
                        extracted["acceptance-statement"],
                        extracted["acceptance-statement-signature"],
                        public_key_path=public_key,
                    )
                    if not statement_sig_ok:
                        errors.extend(
                            f"acceptance statement signature: {error}"
                            for error in statement_sig_errors
                        )
                    details["acceptance_statement_signature_verified"] = statement_sig_ok

                    if str(manifest.get("source_run_id", "")) != source_run_id:
                        errors.append("acceptance manifest source_run_id mismatch")
                    if str(manifest.get("profile_id", "")) != str(profile["id"]):
                        errors.append("acceptance manifest profile_id mismatch")
                    if str(manifest.get("profile_version", "")) != str(profile["version"]):
                        errors.append("acceptance manifest profile_version mismatch")
                    if str(manifest.get("profile_sha256", "")) != profile_sha256:
                        errors.append("acceptance manifest profile_sha256 mismatch")
                    if str(manifest.get("policy_status", "")) != "PASS":
                        errors.append("acceptance manifest policy_status is not PASS")
                    if str(manifest.get("handoff_sha256", "")) != sha256_file(handoff):
                        errors.append("acceptance manifest handoff_sha256 mismatch")
                    if manifest_schema == 2 and str(
                        manifest.get("trusted_artifact_sha256", "")
                    ) != trusted_artifact_sha256:
                        errors.append("acceptance manifest trusted_artifact_sha256 mismatch")

                    if signature_path is not None:
                        outer_ok, outer_errors, _ = verify_signature(
                            pack,
                            signature_path,
                            public_key_path=public_key,
                        )
                        if not outer_ok:
                            errors.extend(
                                f"acceptance envelope signature: {error}"
                                for error in outer_errors
                            )
                        details["envelope_signature_verified"] = outer_ok
    except (
        OSError,
        ValueError,
        KeyError,
        zipfile.BadZipFile,
        json.JSONDecodeError,
    ) as exc:
        errors.append(str(exc))

    details["pack_sha256"] = sha256_file(pack) if pack.is_file() else ""
    details["valid"] = not errors
    return not errors, errors, details


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create or verify a customer-specific acceptance envelope over a trust handoff"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create")
    create.add_argument("--handoff", required=True)
    create.add_argument("--handoff-signature", required=True)
    create.add_argument("--public-key", default=".abl/keys/attestation-public.json")
    create.add_argument("--private-key", default=".abl/keys/attestation-private.json")
    create.add_argument("--policy", required=True, help="path or builtin:<name>")
    create.add_argument("--output", default="reports/customer-acceptance-envelope.zip")

    verify = sub.add_parser("verify")
    verify.add_argument("envelope")
    verify.add_argument("--signature", default=None)

    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            pack, signature, summary = create_acceptance_pack(
                args.handoff,
                handoff_signature_path=args.handoff_signature,
                public_key_path=args.public_key,
                private_key_path=args.private_key,
                policy_path=args.policy,
                output_path=args.output,
            )
            print("CUSTOMER ACCEPTANCE ENVELOPE")
            print(f"  run:       {summary.source_run_id}")
            print(f"  policy:    {summary.profile_id}@{summary.profile_version}")
            print(f"  status:    {summary.policy_status}")
            if summary.trusted_artifact_sha256:
                print(f"  artifact:  {summary.trusted_artifact_sha256}")
            print(f"  envelope:  {pack}")
            print(f"  signature: {signature}")
            return 0

        ok, errors, details = verify_acceptance_pack(
            args.envelope,
            signature_path=args.signature,
        )
        print(json.dumps(details, indent=2, sort_keys=True))
        for error in errors:
            print(f"ERROR: {error}")
        return 0 if ok else 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
