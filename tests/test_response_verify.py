import json
from pathlib import Path

from agent_baseline_lab.response_verify import verify_response_evidence


def test_verify_response_evidence_requires_stop(tmp_path: Path) -> None:
    path = tmp_path / "response.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "sandbox": "abl-demo",
                "drill_id": "response-test",
                "verified_stopped": False,
                "credential_revocation_tested": False,
            }
        ),
        encoding="utf-8",
    )
    ok, errors, summary = verify_response_evidence(path, expected_sandbox="abl-demo")
    assert not ok
    assert "sandbox stop was not independently verified" in errors
    assert summary["verified_stopped"] is False


def test_verify_response_evidence_distinguishes_revocation(tmp_path: Path) -> None:
    path = tmp_path / "response.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "sandbox": "abl-demo",
                "drill_id": "response-test",
                "verified_stopped": True,
                "credential_revocation_tested": False,
            }
        ),
        encoding="utf-8",
    )
    ok, errors, _ = verify_response_evidence(
        path,
        expected_sandbox="abl-demo",
        require_revocation=True,
    )
    assert not ok
    assert "credential revocation was not tested" in errors
