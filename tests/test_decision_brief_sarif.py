import json
from pathlib import Path

from agent_baseline_lab.decision_brief import build_decision_brief, create_decision_brief
from agent_baseline_lab.sarif_export import build_sarif, export_sarif


def _assessment(*statuses: str) -> dict:
    return {
        "run_id": "abl-test",
        "baseline_version": "v1.0-draft",
        "results": [
            {
                "control_id": f"CON-0{index + 1}",
                "status": status,
                "summary": f"control {index + 1} {status}",
                "evaluator": "test",
                "evidence": [{"path": f"evidence/CON-0{index + 1}/result.json"}],
            }
            for index, status in enumerate(statuses)
        ],
    }


def _trusted(status: str = "VERIFIED", scout: str = "PASS") -> dict:
    return {
        "overall_status": status,
        "scout_status": scout,
        "dockerfile": "sample-app/Dockerfile",
        "checks": [
            {
                "id": "oci-attestation-integrity",
                "status": "PASS" if status == "VERIFIED" else "FAIL",
                "summary": "OCI attestation binding",
                "evidence": {},
            }
        ],
    }


def test_decision_brief_blocks_observed_failures():
    brief = build_decision_brief(
        _assessment("PASS", "FAIL", "PARTIAL"),
        trusted_artifact=_trusted(),
        assurance={"overall_status": "PASS", "blocking_failures": 0},
    )

    assert brief.decision == "BLOCKED"
    assert any("CON-02" in blocker for blocker in brief.blockers)
    assert any("CON-03" in gap for gap in brief.evidence_gaps)
    assert "score" not in json.dumps(brief.to_dict()).lower()


def test_decision_brief_is_conditional_when_only_gaps_remain():
    brief = build_decision_brief(
        _assessment("PASS", "PARTIAL", "MANUAL"),
        trusted_artifact=_trusted(),
        assurance={"overall_status": "PASS", "blocking_failures": 0},
    )

    assert brief.decision == "CONDITIONAL"
    assert brief.blockers == []


def test_decision_brief_can_be_evidence_ready_for_complete_supplied_inputs():
    brief = build_decision_brief(
        _assessment("PASS", "PASS"),
        trusted_artifact=_trusted(),
        assurance={"overall_status": "PASS", "blocking_failures": 0},
        require_trusted_artifact=True,
        require_scout=True,
    )

    assert brief.decision == "EVIDENCE_READY"
    assert brief.evidence_gaps == []


def test_required_trusted_artifact_and_scout_fail_closed():
    brief = build_decision_brief(
        _assessment("PASS"),
        trusted_artifact=_trusted(status="NOT_RUN", scout="NOT_RUN"),
        assurance={"overall_status": "PASS", "blocking_failures": 0},
        require_trusted_artifact=True,
        require_scout=True,
    )

    assert brief.decision == "BLOCKED"
    assert any("requires VERIFIED" in blocker for blocker in brief.blockers)
    assert any("Scout gate requires PASS" in blocker for blocker in brief.blockers)


def test_create_decision_brief_writes_json_and_html(tmp_path: Path):
    assessment = tmp_path / "assessment.json"
    trusted = tmp_path / "trusted.json"
    assurance = tmp_path / "assurance.json"
    assessment.write_text(json.dumps(_assessment("PASS", "PARTIAL")), encoding="utf-8")
    trusted.write_text(json.dumps(_trusted()), encoding="utf-8")
    assurance.write_text(json.dumps({"overall_status": "PASS", "blocking_failures": 0}), encoding="utf-8")

    brief = create_decision_brief(
        assessment,
        trusted_artifact_path=trusted,
        assurance_path=assurance,
        output=tmp_path / "brief.json",
        html_output=tmp_path / "brief.html",
    )

    assert brief.decision == "CONDITIONAL"
    assert (tmp_path / "brief.json").is_file()
    assert "Customer Evidence Decision Brief" in (tmp_path / "brief.html").read_text(encoding="utf-8")


def test_sarif_exports_only_actionable_statuses():
    sarif = build_sarif(_assessment("PASS", "FAIL", "PARTIAL", "MANUAL"), _trusted())
    run = sarif["runs"][0]
    results = run["results"]

    assert sarif["version"] == "2.1.0"
    assert {result["level"] for result in results} == {"error", "warning", "note"}
    assert not any(result["ruleId"] == "ABL-CON-01" for result in results)
    assert any(result["ruleId"] == "ABL-CON-02" and result["level"] == "error" for result in results)
    assert any(result["ruleId"] == "ABL-CON-03" and result["level"] == "warning" for result in results)
    assert any(result["ruleId"] == "ABL-CON-04" and result["level"] == "note" for result in results)


def test_sarif_exports_supply_chain_findings_and_writes_file(tmp_path: Path):
    assessment = tmp_path / "assessment.json"
    trusted = tmp_path / "trusted.json"
    output = tmp_path / "governance.sarif"
    assessment.write_text(json.dumps(_assessment("PASS")), encoding="utf-8")
    trusted_payload = _trusted(status="FAILED", scout="FAIL")
    trusted_payload["checks"] = [
        {"id": "default-non-root-user", "status": "FAIL", "summary": "root user", "evidence": {}},
        {"id": "base-image-reproducibility", "status": "FINDING", "summary": "mutable base", "evidence": {}},
    ]
    trusted.write_text(json.dumps(trusted_payload), encoding="utf-8")

    payload = export_sarif(assessment, trusted_artifact_path=trusted, output=output)

    assert output.is_file()
    rules = {result["ruleId"]: result for result in payload["runs"][0]["results"]}
    assert rules["ABL-SUPPLY-default-non-root-user"]["level"] == "error"
    assert rules["ABL-SUPPLY-base-image-reproducibility"]["level"] == "warning"
