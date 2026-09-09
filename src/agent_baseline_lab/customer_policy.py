from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

import yaml


SUPPORTED_STATUS_REQUIREMENTS = {
    "decision": "decision",
    "trusted_artifact": "trusted_artifact_status",
    "docker_scout": "scout_status",
    "assurance": "assurance_status",
}
SUPPORTED_COUNT_STATUSES = {"PASS", "FAIL", "PARTIAL", "MANUAL", "N/A", "ERROR"}
SUPPORTED_ARTIFACT_FACTS = {
    "sbom_present",
    "provenance_present",
    "subject_bindings_valid",
}
BUILTIN_PROFILE_NAMES = (
    "poc-observe",
    "enterprise-strict",
    "enterprise-supply-chain",
)
BUILTIN_PREFIX = "builtin:"


@dataclass(frozen=True)
class PolicyCheck:
    requirement: str
    status: str
    observed: str | int | bool
    expected: Any
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CustomerPolicyEvaluation:
    schema_version: int
    generated_at: str
    profile_id: str
    profile_version: str
    profile_sha256: str
    source_run_id: str
    trusted_artifact_sha256: str
    status: str
    checks: list[PolicyCheck]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["checks"] = [check.to_dict() for check in self.checks]
        if self.schema_version == 1:
            payload.pop("trusted_artifact_sha256", None)
        return payload


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _builtin_name(source: str | Path) -> str | None:
    value = str(source)
    if not value.startswith(BUILTIN_PREFIX):
        return None
    name = value[len(BUILTIN_PREFIX) :].strip()
    if name not in BUILTIN_PROFILE_NAMES:
        raise ValueError(
            f"unknown built-in policy profile {name!r}; available: "
            + ", ".join(BUILTIN_PROFILE_NAMES)
        )
    return name


def policy_source_bytes(source: str | Path) -> bytes:
    name = _builtin_name(source)
    if name is not None:
        resource = resources.files("agent_baseline_lab.policy_profiles").joinpath(f"{name}.yaml")
        try:
            return resource.read_bytes()
        except (FileNotFoundError, ModuleNotFoundError) as exc:
            raise ValueError(f"built-in policy profile is unavailable: {name}") from exc

    path = Path(source)
    if not path.is_file():
        raise ValueError(f"policy profile does not exist: {path}")
    return path.read_bytes()


def export_builtin_profile(
    name: str,
    output: str | Path,
    *,
    force: bool = False,
) -> Path:
    source = f"{BUILTIN_PREFIX}{name}"
    data = policy_source_bytes(source)
    destination = Path(output)
    if destination.exists() and not force:
        raise ValueError(f"refusing to overwrite existing policy profile: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return destination


def _validate_allowed_rule(requirement: str, rule: Any) -> None:
    if not isinstance(rule, dict):
        raise ValueError(f"policy requirement {requirement} must be an object")
    allowed = rule.get("allowed")
    if not isinstance(allowed, list) or not allowed or not all(
        isinstance(value, str) and value for value in allowed
    ):
        raise ValueError(
            f"policy requirement {requirement}.allowed must be a non-empty string list"
        )


def load_policy_profile(source: str | Path) -> tuple[dict[str, Any], str]:
    data = policy_source_bytes(source)
    label = str(source)
    try:
        payload = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"invalid policy profile YAML {label}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("policy profile must contain a YAML object")

    schema_version = payload.get("schema_version")
    if schema_version not in {1, 2}:
        raise ValueError("unsupported policy profile schema_version")

    profile_id = str(payload.get("id", "")).strip()
    version = str(payload.get("version", "")).strip()
    if not profile_id or not version:
        raise ValueError("policy profile requires non-empty id and version")

    requirements = payload.get("requirements")
    if not isinstance(requirements, dict) or not requirements:
        raise ValueError("policy profile requirements must be a non-empty object")

    supported = {*SUPPORTED_STATUS_REQUIREMENTS, "max_assessment_counts"}
    if schema_version >= 2:
        supported.update({"trusted_artifact_checks", "artifact_facts"})
    unknown = set(requirements) - supported
    if unknown:
        raise ValueError("unsupported policy requirement(s): " + ", ".join(sorted(unknown)))

    for name in SUPPORTED_STATUS_REQUIREMENTS:
        if name in requirements:
            _validate_allowed_rule(name, requirements[name])

    count_limits = requirements.get("max_assessment_counts", {})
    if not isinstance(count_limits, dict):
        raise ValueError("max_assessment_counts must be an object")
    for status, limit in count_limits.items():
        if status not in SUPPORTED_COUNT_STATUSES:
            raise ValueError(f"unsupported assessment status in policy: {status}")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise ValueError(
                f"assessment count limit for {status} must be a non-negative integer"
            )

    artifact_checks = requirements.get("trusted_artifact_checks", {})
    if not isinstance(artifact_checks, dict):
        raise ValueError("trusted_artifact_checks must be an object")
    for check_id, rule in artifact_checks.items():
        if not isinstance(check_id, str) or not check_id.strip():
            raise ValueError("trusted_artifact_checks contains an empty check id")
        _validate_allowed_rule(f"trusted_artifact_checks.{check_id}", rule)

    artifact_facts = requirements.get("artifact_facts", {})
    if not isinstance(artifact_facts, dict):
        raise ValueError("artifact_facts must be an object")
    unknown_facts = set(artifact_facts) - SUPPORTED_ARTIFACT_FACTS
    if unknown_facts:
        raise ValueError("unsupported artifact fact(s): " + ", ".join(sorted(unknown_facts)))
    for fact, expected in artifact_facts.items():
        if not isinstance(expected, bool):
            raise ValueError(f"artifact fact requirement {fact} must be boolean")

    return payload, _sha256_bytes(_canonical_json(payload))


def _load_json_object(path: str | Path, *, label: str) -> tuple[dict[str, Any], str]:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"{label} does not exist: {source}")
    data = source.read_bytes()
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label} JSON {source}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return payload, _sha256_bytes(data)


def _artifact_check_map(artifact: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if artifact is None:
        return {}
    checks = artifact.get("checks", [])
    if not isinstance(checks, list):
        raise ValueError("trusted artifact checks must be an array")
    mapped: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(checks, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"trusted artifact check {index} is malformed")
        check_id = str(item.get("id", "")).strip()
        if not check_id:
            raise ValueError(f"trusted artifact check {index} has no id")
        if check_id in mapped:
            raise ValueError(f"trusted artifact contains duplicate check id: {check_id}")
        mapped[check_id] = item
    return mapped


def _artifact_fact_values(
    artifact_checks: dict[str, dict[str, Any]],
) -> dict[str, bool]:
    integrity = artifact_checks.get("oci-attestation-integrity")
    if integrity is None:
        return {}
    evidence = integrity.get("evidence", {})
    if not isinstance(evidence, dict):
        return {}
    summary = evidence.get("summary", {})
    if not isinstance(summary, dict):
        return {}
    values: dict[str, bool] = {}
    for name in SUPPORTED_ARTIFACT_FACTS:
        value = summary.get(name)
        if isinstance(value, bool):
            values[name] = value
    return values


def _evaluation_claims_boundary(schema_version: int) -> str:
    if schema_version == 1:
        return (
            "This result states whether the supplied customer decision satisfies the exact versioned "
            "acceptance profile identified by profile_sha256. It does not independently recreate the "
            "underlying Docker, Agent Baseline, supply-chain, lineage or assurance evidence and is not "
            "production authorization or compliance certification."
        )
    return (
        "This result states whether the supplied customer decision and, when required by the profile, "
        "the supplied trusted-artifact evidence satisfy the exact versioned acceptance profile identified "
        "by profile_sha256. trusted_artifact_sha256 binds any artifact-aware result to the evaluated JSON. "
        "The evaluation does not recreate Docker execution, establish external signer identity, authorize "
        "production, or constitute Docker/compliance certification."
    )


def evaluate_policy(
    profile: dict[str, Any],
    decision: dict[str, Any],
    *,
    profile_sha256: str,
    trusted_artifact: dict[str, Any] | None = None,
    trusted_artifact_sha256: str = "",
    generated_at: str | None = None,
    evaluation_schema_version: int = 2,
) -> CustomerPolicyEvaluation:
    if evaluation_schema_version not in {1, 2}:
        raise ValueError("unsupported customer policy evaluation schema_version")
    if evaluation_schema_version == 1 and int(profile.get("schema_version", 1)) != 1:
        raise ValueError("policy schema v2 cannot be represented by evaluation schema v1")

    requirements = profile["requirements"]
    checks: list[PolicyCheck] = []

    for requirement, field in SUPPORTED_STATUS_REQUIREMENTS.items():
        if requirement not in requirements:
            continue
        allowed = [str(value) for value in requirements[requirement]["allowed"]]
        observed = str(decision.get(field, "NOT_PRESENT"))
        passed = observed in allowed
        checks.append(
            PolicyCheck(
                requirement=requirement,
                status="PASS" if passed else "FAIL",
                observed=observed,
                expected={"allowed": allowed},
                message=(
                    f"{requirement} observed {observed!r}, allowed by profile."
                    if passed
                    else f"{requirement} observed {observed!r}; allowed values are {allowed}."
                ),
            )
        )

    counts = decision.get("assessment_counts", {})
    if not isinstance(counts, dict):
        counts = {}
    for status, limit in sorted(requirements.get("max_assessment_counts", {}).items()):
        raw = counts.get(status, 0)
        observed = raw if isinstance(raw, int) and not isinstance(raw, bool) else -1
        passed = observed >= 0 and observed <= limit
        checks.append(
            PolicyCheck(
                requirement=f"assessment_count:{status}",
                status="PASS" if passed else "FAIL",
                observed=observed,
                expected={"maximum": limit},
                message=(
                    f"{status} count {observed} is within maximum {limit}."
                    if passed
                    else f"{status} count {observed} exceeds or cannot satisfy maximum {limit}."
                ),
            )
        )

    artifact_checks = _artifact_check_map(trusted_artifact)
    for check_id, rule in sorted(requirements.get("trusted_artifact_checks", {}).items()):
        allowed = [str(value) for value in rule["allowed"]]
        item = artifact_checks.get(check_id)
        observed = str(item.get("status", "NOT_PRESENT")) if item else "NOT_PRESENT"
        passed = observed in allowed
        checks.append(
            PolicyCheck(
                requirement=f"trusted_artifact_check:{check_id}",
                status="PASS" if passed else "FAIL",
                observed=observed,
                expected={"allowed": allowed},
                message=(
                    f"trusted artifact check {check_id!r} observed {observed!r}, allowed by profile."
                    if passed
                    else f"trusted artifact check {check_id!r} observed {observed!r}; allowed values are {allowed}."
                ),
            )
        )

    facts = _artifact_fact_values(artifact_checks)
    for fact, expected in sorted(requirements.get("artifact_facts", {}).items()):
        observed: str | bool = facts.get(fact, "NOT_PRESENT")
        passed = isinstance(observed, bool) and observed is expected
        checks.append(
            PolicyCheck(
                requirement=f"artifact_fact:{fact}",
                status="PASS" if passed else "FAIL",
                observed=observed,
                expected={"equals": expected},
                message=(
                    f"artifact fact {fact!r} is {observed}, matching the profile."
                    if passed
                    else f"artifact fact {fact!r} observed {observed!r}; expected {expected}."
                ),
            )
        )

    status = "PASS" if checks and all(check.status == "PASS" for check in checks) else "FAIL"
    return CustomerPolicyEvaluation(
        schema_version=evaluation_schema_version,
        generated_at=generated_at or _utc_now(),
        profile_id=str(profile["id"]),
        profile_version=str(profile["version"]),
        profile_sha256=profile_sha256,
        source_run_id=str(decision.get("assessment_run_id", "")),
        trusted_artifact_sha256=(
            trusted_artifact_sha256 if evaluation_schema_version >= 2 else ""
        ),
        status=status,
        checks=checks,
        claims_boundary=_evaluation_claims_boundary(evaluation_schema_version),
    )


def create_policy_evaluation(
    profile_path: str | Path,
    decision_path: str | Path,
    *,
    trusted_artifact_path: str | Path | None = None,
    output: str | Path,
) -> CustomerPolicyEvaluation:
    profile, profile_sha256 = load_policy_profile(profile_path)
    decision, _ = _load_json_object(decision_path, label="customer decision")
    artifact: dict[str, Any] | None = None
    artifact_sha256 = ""
    if trusted_artifact_path is not None:
        artifact, artifact_sha256 = _load_json_object(
            trusted_artifact_path,
            label="trusted artifact",
        )
    evaluation = evaluate_policy(
        profile,
        decision,
        profile_sha256=profile_sha256,
        trusted_artifact=artifact,
        trusted_artifact_sha256=artifact_sha256,
        evaluation_schema_version=2,
    )
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(evaluation.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return evaluation


def verify_policy_evaluation(
    evaluation_path: str | Path,
    profile_path: str | Path,
    decision_path: str | Path,
    *,
    trusted_artifact_path: str | Path | None = None,
) -> tuple[bool, list[str], CustomerPolicyEvaluation]:
    evaluation_file = Path(evaluation_path)
    try:
        existing = json.loads(evaluation_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read policy evaluation {evaluation_file}: {exc}") from exc
    if not isinstance(existing, dict):
        raise ValueError("policy evaluation must contain a JSON object")

    evaluation_schema = existing.get("schema_version")
    if evaluation_schema not in {1, 2}:
        raise ValueError("unsupported customer policy evaluation schema_version")

    profile, profile_sha256 = load_policy_profile(profile_path)
    decision, _ = _load_json_object(decision_path, label="customer decision")
    artifact: dict[str, Any] | None = None
    artifact_sha256 = ""
    if trusted_artifact_path is not None:
        artifact, artifact_sha256 = _load_json_object(
            trusted_artifact_path,
            label="trusted artifact",
        )

    recomputed = evaluate_policy(
        profile,
        decision,
        profile_sha256=profile_sha256,
        trusted_artifact=artifact,
        trusted_artifact_sha256=artifact_sha256,
        generated_at=str(existing.get("generated_at", "")) or _utc_now(),
        evaluation_schema_version=int(evaluation_schema),
    )
    expected = recomputed.to_dict()
    fields = [
        "schema_version",
        "generated_at",
        "profile_id",
        "profile_version",
        "profile_sha256",
        "source_run_id",
        "status",
        "checks",
        "claims_boundary",
    ]
    if int(evaluation_schema) >= 2:
        fields.insert(6, "trusted_artifact_sha256")

    errors: list[str] = []
    for field in fields:
        if existing.get(field) != expected.get(field):
            errors.append(f"policy evaluation mismatch: {field}")
    return not errors, errors, recomputed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate customer evidence against a versioned acceptance policy"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    list_profiles = sub.add_parser("list-profiles")
    list_profiles.set_defaults(action="list-profiles")

    export = sub.add_parser("export-profile")
    export.add_argument("name", choices=BUILTIN_PROFILE_NAMES)
    export.add_argument("--output", required=True)
    export.add_argument("--force", action="store_true")

    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("profile", help="path or builtin:<name>")
    evaluate.add_argument("decision")
    evaluate.add_argument(
        "--trusted-artifact",
        default=None,
        help="trusted-artifact JSON required by artifact-aware policy profiles",
    )
    evaluate.add_argument("--output", default="reports/customer-policy-evaluation.json")

    verify = sub.add_parser("verify")
    verify.add_argument("evaluation")
    verify.add_argument("profile", help="path or builtin:<name>")
    verify.add_argument("decision")
    verify.add_argument(
        "--trusted-artifact",
        default=None,
        help="trusted-artifact JSON used when the evaluation is artifact-aware",
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "list-profiles":
            for name in BUILTIN_PROFILE_NAMES:
                print(name)
            return 0
        if args.command == "export-profile":
            output = export_builtin_profile(args.name, args.output, force=args.force)
            print(output)
            return 0
        if args.command == "evaluate":
            result = create_policy_evaluation(
                args.profile,
                args.decision,
                trusted_artifact_path=args.trusted_artifact,
                output=args.output,
            )
            print("CUSTOMER POLICY EVALUATION")
            print(f"  profile: {result.profile_id}@{result.profile_version}")
            print(f"  digest:  {result.profile_sha256}")
            if result.trusted_artifact_sha256:
                print(f"  artifact: {result.trusted_artifact_sha256}")
            print(f"  status:  {result.status}")
            return 0 if result.status == "PASS" else 1

        ok, errors, result = verify_policy_evaluation(
            args.evaluation,
            args.profile,
            args.decision,
            trusted_artifact_path=args.trusted_artifact,
        )
        print("CUSTOMER POLICY VERIFICATION")
        print(f"  profile: {result.profile_id}@{result.profile_version}")
        print(f"  status:  {'VERIFIED' if ok else 'FAILED'}")
        for error in errors:
            print(f"ERROR: {error}")
        return 0 if ok else 1
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
