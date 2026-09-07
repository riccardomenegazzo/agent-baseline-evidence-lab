import json
from pathlib import Path

import pytest

from agent_baseline_lab import response_link


def test_create_response_link_binds_both_artifacts(tmp_path: Path, monkeypatch):
    assessment = tmp_path / "evidence" / "abl-test"
    assessment.mkdir(parents=True)
    (assessment / "manifest.sha256.json").write_text("{}\n", encoding="utf-8")
    (assessment / "assessment.json").write_text(
        json.dumps({"run_id": "abl-test"}),
        encoding="utf-8",
    )
    response = tmp_path / "response.json"
    response.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        response_link,
        "verify_bundle",
        lambda root: (
            True,
            [],
            {"manifest_sha256": "manifest", "trace_head_sha256": "trace-head"},
        ),
    )
    monkeypatch.setattr(
        response_link,
        "verify_response_evidence",
        lambda path, expected_sandbox, require_revocation: (
            True,
            [],
            {
                "verified_stopped": True,
                "credential_revocation_tested": True,
                "credential_revocation_scope": "sandbox-custom-secret-binding",
                "drill_id": "response-test",
            },
        ),
    )

    output = tmp_path / "response-link.json"
    statement = response_link.create_response_link(
        assessment,
        response,
        output,
        expected_sandbox="abl-demo",
        require_revocation=True,
    )

    assert output.exists()
    assert statement["predicateType"] == response_link.PREDICATE_TYPE
    assert len(statement["subject"]) == 2
    assert statement["predicate"]["assessmentRunId"] == "abl-test"
    assert statement["predicate"]["claims"]["sandboxStopVerified"] is True
    assert (
        statement["predicate"]["claims"][
            "sandboxScopedCredentialBindingRevocationVerified"
        ]
        is True
    )
    assert statement["predicate"]["signed"] is False


def test_create_response_link_rejects_unverified_response(tmp_path: Path, monkeypatch):
    assessment = tmp_path / "evidence" / "abl-test"
    assessment.mkdir(parents=True)
    (assessment / "manifest.sha256.json").write_text("{}\n", encoding="utf-8")
    (assessment / "assessment.json").write_text(
        json.dumps({"run_id": "abl-test"}),
        encoding="utf-8",
    )
    response = tmp_path / "response.json"
    response.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        response_link,
        "verify_bundle",
        lambda root: (True, [], {"trace_head_sha256": "trace-head"}),
    )
    monkeypatch.setattr(
        response_link,
        "verify_response_evidence",
        lambda path, expected_sandbox, require_revocation: (
            False,
            ["sandbox stop was not independently verified"],
            {},
        ),
    )

    with pytest.raises(ValueError, match="response evidence does not satisfy requested claims"):
        response_link.create_response_link(
            assessment,
            response,
            tmp_path / "response-link.json",
            expected_sandbox="abl-demo",
        )
