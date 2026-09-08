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
BUILTIN_PROFILE_NAMES = ("poc-observe", "enterprise-strict")
BUILTIN_PREFIX = "builtin:"


@dataclass(frozen=True)
class PolicyCheck:
    requirement: str
    status: str
    observed: str | int
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
    status: str
    checks: list[PolicyCheck]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["checks"] = [check.to_dict() for check in self.checks]
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


def load_policy_profile(source: str | Path) -> tuple[dict[str, Any], str]:
    data = policy_source_bytes(source)
    label = str(source)
    try:
        payload = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"invalid policy profile YAML {label}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("policy profile must contain a YAML object")
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported policy profile schema_version")

    profile_id = str(payload.get("id", "")).strip()
    version = str(payload.get("version", "")).strip()
    if not profile_id or not version:
        raise ValueError("policy profile requires non-empty id and version")

    requirements = payload.get("requirements")
    if not isinstance(requirements, dict) or not requirements:
        raise ValueError("policy profile requirements must be a non-empty object")

    unknown = set(requirements) - {*SUPPORTED_STATUS_REQUIREMENTS, "max_assessment_counts"}
    if unknown:
        raise ValueError("unsupported policy requirement(s): " + ", ".join(sorted(unknown)))

    for name in SUPPORTED_STATUS_REQUIREMENTS:
        if name not in requirements:
            continue
        rule = requirements[name]
        if not isinstance(rule, dict):
            raise ValueError(f"policy requirement {name} must be an object")
        allowed = rule.get("allowed")
        if not isinstance(allowed, list) or not allowed or not all(
            isinstance(value, str) and value for value in allowed
        ):
            raise ValueError(
                f"policy requirement {name}.allowed must be a non-empty string list"
            )

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

    return payload, _sha256_bytes(_canonical_json(payload))


def _load_decision(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"customer decision does not exist: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid customer decision JSON {source}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("customer decision must contain a JSON object")
    return payload


def evaluate_policy(
    profile: dict[str, Any],
    decision: dict[str, Any],
    *,
    profile_sha256: str,
    generated_at: str | None = None,
) -> CustomerPolicyEvaluation:
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

    status = "PASS" if checks and all(check.status == "PASS" for check in checks) else "FAIL"
    return CustomerPolicyEvaluation(
        schema_version=1,
        generated_at=generated_at or _utc_now(),
        profile_id=str(profile["id"]),
        profile_version=str(profile["version"]),
        profile_sha256=profile_sha256,
        source_run_id=str(decision.get("assessment_run_id", "")),
        status=status,
        checks=checks,
        claims_boundary=(
            "This result states whether the supplied customer decision satisfies the exact versioned "
            "acceptance profile identified by profile_sha256. It does not independently recreate the "
            "underlying Docker, Agent Baseline, supply-chain, lineage or assurance evidence and is not "
            "production authorization or compliance certification."
        ),
    )


def create_policy_evaluation(
    profile_path: str | Path,
    decision_path: str | Path,
    *,
    output: str | Path,
) -> CustomerPolicyEvaluation:
    profile, profile_sha256 = load_policy_profile(profile_path)
    decision = _load_decision(decision_path)
    evaluation = evaluate_policy(profile, decision, profile_sha256=profile_sha256)
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
) -> tuple[bool, list[str], CustomerPolicyEvaluation]:
    evaluation_file = Path(evaluation_path)
    try:
        existing = json.loads(evaluation_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read policy evaluation {evaluation_file}: {exc}") from exc
    if not isinstance(existing, dict):
        raise ValueError("policy evaluation must contain a JSON object")

    profile, profile_sha256 = load_policy_profile(profile_path)
    decision = _load_decision(decision_path)
    recomputed = evaluate_policy(
        profile,
        decision,
        profile_sha256=profile_sha256,
        generated_at=str(existing.get("generated_at", "")) or _utc_now(),
    )
    expected = recomputed.to_dict()
    errors: list[str] = []
    for field in (
        "schema_version",
        "generated_at",
        "profile_id",
        "profile_version",
        "profile_sha256",
        "source_run_id",
        "status",
        "checks",
        "claims_boundary",
    ):
        if existing.get(field) != expected.get(field):
            errors.append(f"policy evaluation mismatch: {field}")
    return not errors, errors, recomputed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate a customer decision against a versioned acceptance policy"
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
    evaluate.add_argument("--output", default="reports/customer-policy-evaluation.json")

    verify = sub.add_parser("verify")
    verify.add_argument("evaluation")
    verify.add_argument("profile", help="path or builtin:<name>")
    verify.add_argument("decision")

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
            result = create_policy_evaluation(args.profile, args.decision, output=args.output)
            print("CUSTOMER POLICY EVALUATION")
            print(f"  profile: {result.profile_id}@{result.profile_version}")
            print(f"  digest:  {result.profile_sha256}")
            print(f"  status:  {result.status}")
            return 0 if result.status == "PASS" else 1

        ok, errors, result = verify_policy_evaluation(
            args.evaluation,
            args.profile,
            args.decision,
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
