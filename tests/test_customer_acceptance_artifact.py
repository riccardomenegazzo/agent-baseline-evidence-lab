import json
from pathlib import Path

import pytest

from agent_baseline_lab.customer_acceptance import (
    create_acceptance_pack,
    verify_acceptance_pack,
)
from agent_baseline_lab.signing import generate_keypair, sign_file
from agent_baseline_lab.trust_handoff import create_handoff_pack


def _write_decision(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "assessment_run_id": "abl-supply-chain-test",
                "decision": "EVIDENCE_READY",
                "baseline_version": "v1.0-draft",
                "assessment_counts": {
                    "PASS": 35,
                    "FAIL": 0,
                    "ERROR": 0,
                    "PARTIAL": 0,
                    "MANUAL": 0,
                },
                "trusted_artifact_status": "VERIFIED",
                "scout_status": "PASS",
                "assurance_status": "PASS",
                "blockers": [],
                "evidence_gaps": [],
                "observed_strengths": [],
                "recommended_next_actions": [],
                "source_artifacts": {},
                "claims_boundary": "test decision",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _write_artifact(path: Path, *, subject_bindings_valid: bool = True) -> Path:
    path.write_text(
        json.dumps(
            {
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
                        "summary": "OCI attestation graph verified.",
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
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _handoff(root: Path, *, include_artifact: bool = True, subject_bindings_valid: bool = True):
    private_key, public_key = generate_keypair(
        root / ".abl" / "keys" / "attestation-private.json",
        root / ".abl" / "keys" / "attestation-public.json",
    )
    decision = _write_decision(root / "customer-decision.json")
    sources = [
        ("public-verification-key", public_key, "trust/attestation-public.json"),
        ("customer-decision", decision, "decision/customer-decision.json"),
    ]
    if include_artifact:
        artifact = _write_artifact(
            root / "trusted-artifact.json",
            subject_bindings_valid=subject_bindings_valid,
        )
        sources.append(
            ("trusted-artifact", artifact, "supply-chain/trusted-artifact.json")
        )
    handoff, _ = create_handoff_pack(
        root,
        run_id="abl-supply-chain-test",
        output_path=root / "customer-trust-handoff.zip",
        dry_run=False,
        sources=sources,
    )
    handoff_signature = root / "customer-trust-handoff.zip.ed25519.json"
    sign_file(handoff, private_key, handoff_signature)
    return handoff, handoff_signature, private_key, public_key


def test_artifact_aware_acceptance_envelope_verifies_nested_supply_chain_evidence(
    tmp_path: Path,
):
    root = tmp_path / "project"
    root.mkdir()
    handoff, handoff_signature, private_key, public_key = _handoff(root)

    envelope, signature, summary = create_acceptance_pack(
        handoff,
        handoff_signature_path=handoff_signature,
        public_key_path=public_key,
        private_key_path=private_key,
        policy_path="builtin:enterprise-supply-chain",
        output_path=root / "customer-acceptance-envelope.zip",
    )
    ok, errors, details = verify_acceptance_pack(envelope, signature_path=signature)

    assert ok is True, errors
    assert summary.schema_version == 2
    assert summary.profile_id == "enterprise-supply-chain"
    assert len(summary.trusted_artifact_sha256) == 64
    assert details["policy_recomputed_status"] == "PASS"
    assert details["trusted_artifact_sha256"] == summary.trusted_artifact_sha256
    assert details["nested_trusted_artifact_sha256"] == summary.trusted_artifact_sha256


def test_artifact_aware_acceptance_fails_when_handoff_has_no_trusted_artifact(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    handoff, handoff_signature, private_key, public_key = _handoff(
        root,
        include_artifact=False,
    )

    with pytest.raises(ValueError, match="customer policy is not satisfied") as exc:
        create_acceptance_pack(
            handoff,
            handoff_signature_path=handoff_signature,
            public_key_path=public_key,
            private_key_path=private_key,
            policy_path="builtin:enterprise-supply-chain",
            output_path=root / "customer-acceptance-envelope.zip",
        )

    assert "trusted_artifact_check:oci-attestation-integrity" in str(exc.value)
    assert "artifact_fact:sbom_present" in str(exc.value)


def test_artifact_aware_acceptance_fails_on_invalid_subject_binding_fact(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    handoff, handoff_signature, private_key, public_key = _handoff(
        root,
        subject_bindings_valid=False,
    )

    with pytest.raises(ValueError, match="artifact_fact:subject_bindings_valid"):
        create_acceptance_pack(
            handoff,
            handoff_signature_path=handoff_signature,
            public_key_path=public_key,
            private_key_path=private_key,
            policy_path="builtin:enterprise-supply-chain",
            output_path=root / "customer-acceptance-envelope.zip",
        )
