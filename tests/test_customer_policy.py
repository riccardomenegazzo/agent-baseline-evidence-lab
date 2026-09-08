import json
from pathlib import Path

import pytest
import yaml

from agent_baseline_lab.customer_policy import (
    create_policy_evaluation,
    load_policy_profile,
    verify_policy_evaluation,
)


def _profile(tmp_path: Path, *, strict: bool = True) -> Path:
    path = tmp_path / "profile.yaml"
    requirements = {
        "decision": {"allowed": ["EVIDENCE_READY"] if strict else ["EVIDENCE_READY", "CONDITIONAL"]},
        "trusted_artifact": {"allowed": ["VERIFIED"]},
        "assurance": {"allowed": ["PASS"]},
        "max_assessment_counts": {"FAIL": 0, "ERROR": 0},
    }
    if strict:
        requirements["docker_scout"] = {"allowed": ["PASS"]}
        requirements["max_assessment_counts"].update({"PARTIAL": 0, "MANUAL": 0})
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "id": "enterprise-strict" if strict else "poc-observe",
                "version": "1.0.0",
                "description": "test policy",
                "requirements": requirements,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return path


def _decision(tmp_path: Path, **overrides) -> Path:
    payload = {
        "assessment_run_id": "abl-test",
        "decision": "EVIDENCE_READY",
        "trusted_artifact_status": "VERIFIED",
        "scout_status": "PASS",
        "assurance_status": "PASS",
        "assessment_counts": {
            "PASS": 35,
            "FAIL": 0,
            "ERROR": 0,
            "PARTIAL": 0,
            "MANUAL": 0,
        },
    }
    payload.update(overrides)
    path = tmp_path / "decision.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_strict_profile_passes_complete_evidence(tmp_path: Path):
    profile = _profile(tmp_path)
    decision = _decision(tmp_path)
    output = tmp_path / "evaluation.json"

    result = create_policy_evaluation(profile, decision, output=output)

    assert result.status == "PASS"
    assert result.profile_id == "enterprise-strict"
    assert len(result.profile_sha256) == 64
    assert all(check.status == "PASS" for check in result.checks)


def test_strict_profile_fails_scout_and_partial_gap(tmp_path: Path):
    profile = _profile(tmp_path)
    decision = _decision(
        tmp_path,
        scout_status="FAIL",
        assessment_counts={"PASS": 34, "FAIL": 0, "ERROR": 0, "PARTIAL": 1, "MANUAL": 0},
    )

    result = create_policy_evaluation(profile, decision, output=tmp_path / "evaluation.json")

    assert result.status == "FAIL"
    failed = {check.requirement for check in result.checks if check.status == "FAIL"}
    assert "docker_scout" in failed
    assert "assessment_count:PARTIAL" in failed


def test_observe_profile_allows_conditional_without_scout_gate(tmp_path: Path):
    profile = _profile(tmp_path, strict=False)
    decision = _decision(
        tmp_path,
        decision="CONDITIONAL",
        scout_status="NOT_RUN",
        assessment_counts={"PASS": 34, "FAIL": 0, "ERROR": 0, "PARTIAL": 1},
    )

    result = create_policy_evaluation(profile, decision, output=tmp_path / "evaluation.json")

    assert result.status == "PASS"
    assert not any(check.requirement == "docker_scout" for check in result.checks)


def test_verifier_detects_evaluation_tampering(tmp_path: Path):
    profile = _profile(tmp_path)
    decision = _decision(tmp_path)
    output = tmp_path / "evaluation.json"
    create_policy_evaluation(profile, decision, output=output)

    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["status"] = "FAIL"
    output.write_text(json.dumps(payload), encoding="utf-8")

    ok, errors, _ = verify_policy_evaluation(output, profile, decision)

    assert ok is False
    assert "policy evaluation mismatch: status" in errors


def test_profile_digest_changes_with_policy_semantics(tmp_path: Path):
    profile = _profile(tmp_path)
    payload, digest_before = load_policy_profile(profile)
    payload["requirements"]["docker_scout"]["allowed"].append("NOT_RUN")
    profile.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    _, digest_after = load_policy_profile(profile)

    assert digest_before != digest_after


@pytest.mark.parametrize(
    "payload,error",
    [
        (
            {
                "schema_version": 2,
                "id": "x",
                "version": "1",
                "requirements": {"decision": {"allowed": ["EVIDENCE_READY"]}},
            },
            "schema_version",
        ),
        (
            {
                "schema_version": 1,
                "id": "x",
                "version": "1",
                "requirements": {"unknown": {}},
            },
            "unsupported policy requirement",
        ),
        (
            {
                "schema_version": 1,
                "id": "x",
                "version": "1",
                "requirements": {"max_assessment_counts": {"FAIL": -1}},
            },
            "non-negative integer",
        ),
    ],
)
def test_policy_profile_validation_fails_closed(tmp_path: Path, payload: dict, error: str):
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=error):
        load_policy_profile(path)
