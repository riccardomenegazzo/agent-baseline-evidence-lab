import json
from pathlib import Path

import pytest
import yaml

from agent_baseline_lab.customer_policy import (
    create_policy_evaluation,
    evaluate_policy,
    load_policy_profile,
    verify_policy_evaluation,
)


def _decision(path: Path) -> Path:
    payload = {
        "assessment_run_id": "abl-artifact-policy",
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
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _artifact(path: Path, *, subject_bindings_valid: bool = True) -> Path:
    payload = {
        "schema_version": 1,
        "overall_status": "VERIFIED",
        "scout_status": "PASS",
        "checks": [
            {
                "id": "default-non-root-user",
                "status": "PASS",
                "summary": "Final stage runs as app.",
                "evidence": {},
            },
            {
                "id": "runtime-healthcheck",
                "status": "PASS",
                "summary": "HEALTHCHECK is declared.",
                "evidence": {},
            },
            {
                "id": "oci-attestation-integrity",
                "status": "PASS",
                "summary": "OCI attestations verified.",
                "evidence": {
                    "summary": {
                        "sbom_present": True,
                        "provenance_present": True,
                        "subject_bindings_valid": subject_bindings_valid,
                    },
                    "errors": [],
                },
            },
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _profile(path: Path) -> Path:
    payload = {
        "schema_version": 2,
        "id": "artifact-aware",
        "version": "1.0.0",
        "requirements": {
            "decision": {"allowed": ["EVIDENCE_READY"]},
            "trusted_artifact": {"allowed": ["VERIFIED"]},
            "trusted_artifact_checks": {
                "default-non-root-user": {"allowed": ["PASS"]},
                "oci-attestation-integrity": {"allowed": ["PASS"]},
            },
            "artifact_facts": {
                "sbom_present": True,
                "provenance_present": True,
                "subject_bindings_valid": True,
            },
        },
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def test_artifact_aware_policy_passes_and_binds_artifact_digest(tmp_path: Path):
    profile = _profile(tmp_path / "policy.yaml")
    decision = _decision(tmp_path / "decision.json")
    artifact = _artifact(tmp_path / "trusted-artifact.json")
    output = tmp_path / "evaluation.json"

    result = create_policy_evaluation(
        profile,
        decision,
        trusted_artifact_path=artifact,
        output=output,
    )

    assert result.schema_version == 2
    assert result.status == "PASS"
    assert len(result.trusted_artifact_sha256) == 64
    assert all(check.status == "PASS" for check in result.checks)

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["trusted_artifact_sha256"] == result.trusted_artifact_sha256


def test_artifact_aware_policy_fails_when_artifact_is_not_supplied(tmp_path: Path):
    profile = _profile(tmp_path / "policy.yaml")
    decision = _decision(tmp_path / "decision.json")

    result = create_policy_evaluation(
        profile,
        decision,
        output=tmp_path / "evaluation.json",
    )

    assert result.status == "FAIL"
    failed = {check.requirement for check in result.checks if check.status == "FAIL"}
    assert "trusted_artifact_check:default-non-root-user" in failed
    assert "trusted_artifact_check:oci-attestation-integrity" in failed
    assert "artifact_fact:sbom_present" in failed
    assert "artifact_fact:provenance_present" in failed
    assert "artifact_fact:subject_bindings_valid" in failed


def test_artifact_fact_failure_is_visible_without_rewriting_decision(tmp_path: Path):
    profile = _profile(tmp_path / "policy.yaml")
    decision = _decision(tmp_path / "decision.json")
    artifact = _artifact(tmp_path / "trusted-artifact.json", subject_bindings_valid=False)

    result = create_policy_evaluation(
        profile,
        decision,
        trusted_artifact_path=artifact,
        output=tmp_path / "evaluation.json",
    )

    assert result.status == "FAIL"
    failed = [check for check in result.checks if check.status == "FAIL"]
    assert [check.requirement for check in failed] == ["artifact_fact:subject_bindings_valid"]
    original = json.loads(decision.read_text(encoding="utf-8"))
    assert original["decision"] == "EVIDENCE_READY"


def test_verifier_detects_artifact_change_after_evaluation(tmp_path: Path):
    profile = _profile(tmp_path / "policy.yaml")
    decision = _decision(tmp_path / "decision.json")
    artifact = _artifact(tmp_path / "trusted-artifact.json")
    output = tmp_path / "evaluation.json"
    create_policy_evaluation(
        profile,
        decision,
        trusted_artifact_path=artifact,
        output=output,
    )

    _artifact(artifact, subject_bindings_valid=False)
    ok, errors, recomputed = verify_policy_evaluation(
        output,
        profile,
        decision,
        trusted_artifact_path=artifact,
    )

    assert ok is False
    assert recomputed.status == "FAIL"
    assert "policy evaluation mismatch: trusted_artifact_sha256" in errors
    assert "policy evaluation mismatch: status" in errors
    assert "policy evaluation mismatch: checks" in errors


def test_duplicate_trusted_artifact_check_ids_fail_closed(tmp_path: Path):
    profile, digest = load_policy_profile(_profile(tmp_path / "policy.yaml"))
    decision = json.loads(_decision(tmp_path / "decision.json").read_text(encoding="utf-8"))
    artifact_path = _artifact(tmp_path / "trusted-artifact.json")
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["checks"].append(dict(artifact["checks"][0]))

    with pytest.raises(ValueError, match="duplicate check id"):
        evaluate_policy(
            profile,
            decision,
            profile_sha256=digest,
            trusted_artifact=artifact,
        )


def test_schema_v1_evaluation_remains_verifiable(tmp_path: Path):
    profile_path = tmp_path / "legacy.yaml"
    profile_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "id": "legacy",
                "version": "1.0.0",
                "requirements": {"decision": {"allowed": ["EVIDENCE_READY"]}},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    profile, digest = load_policy_profile(profile_path)
    decision_path = _decision(tmp_path / "decision.json")
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    legacy = evaluate_policy(
        profile,
        decision,
        profile_sha256=digest,
        evaluation_schema_version=1,
        generated_at="2026-09-08T00:00:00+00:00",
    )
    output = tmp_path / "legacy-evaluation.json"
    output.write_text(json.dumps(legacy.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    ok, errors, recomputed = verify_policy_evaluation(output, profile_path, decision_path)

    assert ok is True, errors
    assert recomputed.schema_version == 1
    assert "trusted_artifact_sha256" not in legacy.to_dict()


def test_schema_v1_cannot_declare_artifact_requirements(tmp_path: Path):
    profile = tmp_path / "bad.yaml"
    profile.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "id": "bad",
                "version": "1",
                "requirements": {
                    "artifact_facts": {"sbom_present": True},
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsupported policy requirement"):
        load_policy_profile(profile)
