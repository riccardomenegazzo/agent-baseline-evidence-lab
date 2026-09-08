from __future__ import annotations

from pathlib import Path

from agent_baseline_lab import assurance_suite
from agent_baseline_lab.evidence_matrix import VerificationScenario


def _matrix() -> list[VerificationScenario]:
    return [
        VerificationScenario(
            id="single-file-alteration",
            description="",
            internal_verifier_passed=False,
            externally_anchored_verifier_passed=False,
            alteration_detected_internally=True,
            alteration_detected_with_external_anchor=True,
            expected_security_property="integrity",
            finding="",
        ),
        VerificationScenario(
            id="trace-truncation",
            description="",
            internal_verifier_passed=False,
            externally_anchored_verifier_passed=False,
            alteration_detected_internally=True,
            alteration_detected_with_external_anchor=True,
            expected_security_property="completeness",
            finding="",
        ),
        VerificationScenario(
            id="coordinated-rewrite",
            description="",
            internal_verifier_passed=True,
            externally_anchored_verifier_passed=False,
            alteration_detected_internally=False,
            alteration_detected_with_external_anchor=True,
            expected_security_property="independent-verifiability",
            finding="",
        ),
        VerificationScenario(
            id="event-never-emitted",
            description="",
            internal_verifier_passed=True,
            externally_anchored_verifier_passed=True,
            alteration_detected_internally=False,
            alteration_detected_with_external_anchor=False,
            expected_security_property="source-completeness",
            finding="",
        ),
    ]


def _root(tmp_path: Path) -> Path:
    evidence = tmp_path / "evidence" / "abl-test"
    evidence.mkdir(parents=True)
    (evidence / "trace").mkdir()
    (evidence / "trace" / "events.ndjson").write_text("", encoding="utf-8")
    return tmp_path


def test_assurance_suite_passes_with_optional_surfaces_absent(tmp_path: Path, monkeypatch) -> None:
    root = _root(tmp_path)
    monkeypatch.setattr(
        assurance_suite,
        "verify_bundle",
        lambda path: (True, [], {"manifest_sha256": "manifest", "trace_head_sha256": "head"}),
    )
    monkeypatch.setattr(
        assurance_suite,
        "run_verification_matrix",
        lambda *args, **kwargs: (_matrix(), {"key_result": "bounded"}),
    )

    summary = assurance_suite.run_assurance_suite(root)
    statuses = {check.name: check.status for check in summary.checks}

    assert summary.overall_status == "PASS"
    assert summary.blocking_failures == 0
    assert statuses["assessment-bundle-integrity"] == "PASS"
    assert statuses["evidence-trust-boundary-regression"] == "PASS"
    assert statuses["attestation-signature"] == "NOT_RUN"
    assert statuses["behavioral-drift"] == "NOT_RUN"


def test_assurance_suite_fails_on_blocking_bundle_failure(tmp_path: Path, monkeypatch) -> None:
    root = _root(tmp_path)
    monkeypatch.setattr(
        assurance_suite,
        "verify_bundle",
        lambda path: (False, ["digest mismatch"], {"manifest_sha256": "bad"}),
    )
    monkeypatch.setattr(
        assurance_suite,
        "run_verification_matrix",
        lambda *args, **kwargs: (_matrix(), {"key_result": "bounded"}),
    )

    summary = assurance_suite.run_assurance_suite(root)

    assert summary.overall_status == "FAIL"
    assert summary.blocking_failures == 1
