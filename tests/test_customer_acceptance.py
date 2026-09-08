import json
import zipfile
from pathlib import Path

import pytest

from agent_baseline_lab.customer_acceptance import (
    create_acceptance_pack,
    verify_acceptance_pack,
)
from agent_baseline_lab.signing import generate_keypair, sign_file
from agent_baseline_lab.trust_handoff import create_handoff_pack


def _decision(path: Path, *, decision: str = "EVIDENCE_READY", scout: str = "PASS") -> Path:
    payload = {
        "schema_version": 1,
        "assessment_run_id": "abl-accept-test",
        "decision": decision,
        "baseline_version": "v1.0-draft",
        "assessment_counts": {
            "PASS": 35,
            "FAIL": 0,
            "ERROR": 0,
            "PARTIAL": 0,
            "MANUAL": 0,
        },
        "trusted_artifact_status": "VERIFIED",
        "scout_status": scout,
        "assurance_status": "PASS",
        "blockers": [],
        "evidence_gaps": [],
        "observed_strengths": [],
        "recommended_next_actions": [],
        "source_artifacts": {},
        "claims_boundary": "test decision",
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _strict_policy(path: Path) -> Path:
    path.write_text(
        """schema_version: 1
id: enterprise-strict
version: 1.0.0
requirements:
  decision:
    allowed: [EVIDENCE_READY]
  trusted_artifact:
    allowed: [VERIFIED]
  docker_scout:
    allowed: [PASS]
  assurance:
    allowed: [PASS]
  max_assessment_counts:
    FAIL: 0
    ERROR: 0
    PARTIAL: 0
    MANUAL: 0
""",
        encoding="utf-8",
    )
    return path


def _observe_policy(path: Path) -> Path:
    path.write_text(
        """schema_version: 1
id: poc-observe
version: 1.0.0
requirements:
  decision:
    allowed: [EVIDENCE_READY, CONDITIONAL]
  trusted_artifact:
    allowed: [VERIFIED]
  assurance:
    allowed: [PASS]
  max_assessment_counts:
    FAIL: 0
    ERROR: 0
""",
        encoding="utf-8",
    )
    return path


def _handoff(root: Path, *, decision: str = "EVIDENCE_READY", scout: str = "PASS"):
    private_key, public_key = generate_keypair(
        root / ".abl" / "keys" / "attestation-private.json",
        root / ".abl" / "keys" / "attestation-public.json",
    )
    report = _decision(root / "customer-decision.json", decision=decision, scout=scout)
    handoff, _ = create_handoff_pack(
        root,
        run_id="abl-accept-test",
        output_path=root / "customer-trust-handoff.zip",
        dry_run=False,
        sources=[
            ("public-verification-key", public_key, "trust/attestation-public.json"),
            ("customer-decision", report, "decision/customer-decision.json"),
        ],
    )
    handoff_signature = root / "customer-trust-handoff.zip.ed25519.json"
    sign_file(handoff, private_key, handoff_signature)
    return handoff, handoff_signature, private_key, public_key


def test_acceptance_envelope_round_trip(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    handoff, handoff_signature, private_key, public_key = _handoff(root)
    policy = _strict_policy(root / "policy.yaml")

    envelope, signature, summary = create_acceptance_pack(
        handoff,
        handoff_signature_path=handoff_signature,
        public_key_path=public_key,
        private_key_path=private_key,
        policy_path=policy,
        output_path=root / "customer-acceptance-envelope.zip",
    )
    ok, errors, details = verify_acceptance_pack(envelope, signature_path=signature)

    assert ok is True, errors
    assert summary.policy_status == "PASS"
    assert summary.profile_id == "enterprise-strict"
    assert details["nested_handoff_verified"] is True
    assert details["nested_handoff_signature_verified"] is True
    assert details["policy_evaluation_verified"] is True
    assert details["policy_evaluation_signature_verified"] is True
    assert details["acceptance_statement_signature_verified"] is True
    assert details["envelope_signature_verified"] is True


def test_acceptance_creation_fails_closed_when_policy_is_not_satisfied(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    handoff, handoff_signature, private_key, public_key = _handoff(root, scout="FAIL")
    policy = _strict_policy(root / "policy.yaml")

    with pytest.raises(ValueError, match="customer policy is not satisfied"):
        create_acceptance_pack(
            handoff,
            handoff_signature_path=handoff_signature,
            public_key_path=public_key,
            private_key_path=private_key,
            policy_path=policy,
            output_path=root / "customer-acceptance-envelope.zip",
        )


def test_same_handoff_can_be_evaluated_by_different_customer_policies(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    handoff, handoff_signature, private_key, public_key = _handoff(
        root,
        decision="CONDITIONAL",
        scout="NOT_RUN",
    )
    observe = _observe_policy(root / "observe.yaml")
    strict = _strict_policy(root / "strict.yaml")

    envelope, _, summary = create_acceptance_pack(
        handoff,
        handoff_signature_path=handoff_signature,
        public_key_path=public_key,
        private_key_path=private_key,
        policy_path=observe,
        output_path=root / "observe-envelope.zip",
    )

    assert envelope.is_file()
    assert summary.profile_id == "poc-observe"
    with pytest.raises(ValueError, match="customer policy is not satisfied"):
        create_acceptance_pack(
            handoff,
            handoff_signature_path=handoff_signature,
            public_key_path=public_key,
            private_key_path=private_key,
            policy_path=strict,
            output_path=root / "strict-envelope.zip",
        )


def test_acceptance_verifier_detects_profile_tampering(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    handoff, handoff_signature, private_key, public_key = _handoff(root)
    policy = _strict_policy(root / "policy.yaml")
    envelope, _, _ = create_acceptance_pack(
        handoff,
        handoff_signature_path=handoff_signature,
        public_key_path=public_key,
        private_key_path=private_key,
        policy_path=policy,
        output_path=root / "customer-acceptance-envelope.zip",
    )

    tampered = root / "tampered.zip"
    with zipfile.ZipFile(envelope, "r") as source, zipfile.ZipFile(tampered, "w") as target:
        for name in source.namelist():
            data = source.read(name)
            if name == "policy/customer-policy.yaml":
                data = data.replace(b"allowed: [PASS]", b"allowed: [PASS, NOT_RUN]", 1)
            target.writestr(name, data)

    ok, errors, _ = verify_acceptance_pack(tampered)

    assert ok is False
    assert any("digest mismatch" in error or "customer policy" in error for error in errors)
