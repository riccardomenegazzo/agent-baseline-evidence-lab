import json
from pathlib import Path

from agent_baseline_lab import response_link_verify


def test_verify_response_link_accepts_matching_artifacts(tmp_path: Path, monkeypatch):
    assessment = tmp_path / "evidence" / "abl-test"
    assessment.mkdir(parents=True)
    manifest = assessment / "manifest.sha256.json"
    manifest.write_text("{}\n", encoding="utf-8")
    (assessment / "assessment.json").write_text(
        json.dumps({"run_id": "abl-test"}),
        encoding="utf-8",
    )
    response = tmp_path / "response.json"
    response.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        response_link_verify,
        "verify_bundle",
        lambda root: (True, [], {"trace_head_sha256": "trace-head"}),
    )
    monkeypatch.setattr(
        response_link_verify,
        "verify_response_evidence",
        lambda path, expected_sandbox, require_revocation: (
            True,
            [],
            {
                "verified_stopped": True,
                "credential_revocation_tested": True,
            },
        ),
    )

    statement = tmp_path / "link.json"
    statement.write_text(
        json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {
                        "name": "assessment/abl-test/manifest.sha256.json",
                        "digest": {
                            "sha256": response_link_verify.sha256_file(manifest)
                        },
                    },
                    {
                        "name": "response/response.json",
                        "digest": {
                            "sha256": response_link_verify.sha256_file(response)
                        },
                    },
                ],
                "predicateType": response_link_verify.PREDICATE_TYPE,
                "predicate": {
                    "assessmentRunId": "abl-test",
                    "assessmentTraceHeadSha256": "trace-head",
                    "sandbox": "abl-demo",
                    "claims": {
                        "sandboxStopVerified": True,
                        "sandboxScopedCredentialBindingRevocationVerified": True,
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    ok, errors, summary = response_link_verify.verify_response_link(
        statement,
        assessment,
        response,
    )
    assert ok is True
    assert errors == []
    assert summary["run_id"] == "abl-test"
    assert len(summary["statement_sha256"]) == 64


def test_verify_response_link_detects_response_digest_change(tmp_path: Path, monkeypatch):
    assessment = tmp_path / "evidence" / "abl-test"
    assessment.mkdir(parents=True)
    manifest = assessment / "manifest.sha256.json"
    manifest.write_text("{}\n", encoding="utf-8")
    (assessment / "assessment.json").write_text(
        json.dumps({"run_id": "abl-test"}),
        encoding="utf-8",
    )
    response = tmp_path / "response.json"
    response.write_text("changed\n", encoding="utf-8")

    monkeypatch.setattr(
        response_link_verify,
        "verify_bundle",
        lambda root: (True, [], {"trace_head_sha256": "trace-head"}),
    )
    monkeypatch.setattr(
        response_link_verify,
        "verify_response_evidence",
        lambda path, expected_sandbox, require_revocation: (
            True,
            [],
            {
                "verified_stopped": True,
                "credential_revocation_tested": True,
            },
        ),
    )

    statement = tmp_path / "link.json"
    statement.write_text(
        json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {
                        "name": "assessment/abl-test/manifest.sha256.json",
                        "digest": {
                            "sha256": response_link_verify.sha256_file(manifest)
                        },
                    },
                    {
                        "name": "response/response.json",
                        "digest": {"sha256": "0" * 64},
                    },
                ],
                "predicateType": response_link_verify.PREDICATE_TYPE,
                "predicate": {
                    "assessmentRunId": "abl-test",
                    "assessmentTraceHeadSha256": "trace-head",
                    "sandbox": "abl-demo",
                    "claims": {
                        "sandboxStopVerified": True,
                        "sandboxScopedCredentialBindingRevocationVerified": True,
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    ok, errors, _ = response_link_verify.verify_response_link(
        statement,
        assessment,
        response,
    )
    assert ok is False
    assert "response evidence digest does not match response-link subject" in errors
