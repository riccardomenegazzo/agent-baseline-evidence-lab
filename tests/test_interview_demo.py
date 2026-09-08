from pathlib import Path
from types import SimpleNamespace

from agent_baseline_lab import interview_demo
from agent_baseline_lab.models import Status


class _Result:
    def __init__(self, status: Status):
        self.status = status


def test_interview_demo_uses_actual_live_sandbox_and_links_response(tmp_path: Path, monkeypatch):
    session_dir = tmp_path / "agent-runs" / "agent-test"
    session_dir.mkdir(parents=True)
    config = session_dir / "assessment-config.yaml"
    config.write_text("schema_version: 1\n", encoding="utf-8")

    live = SimpleNamespace(
        session_id="agent-test",
        session_dir=str(session_dir),
        sandbox_name="abl-demo-real123",
        workspace=str(tmp_path / "workspace"),
        executed=True,
        returncode=0,
        config_for_assessment=str(config),
    )
    monkeypatch.setattr(interview_demo, "run_agent_task", lambda *args, **kwargs: live)

    evidence = tmp_path / "evidence" / "abl-assessment"
    evidence.mkdir(parents=True)
    (evidence / "manifest.sha256.json").write_text("{}\n", encoding="utf-8")
    report = SimpleNamespace(
        run_id="abl-assessment",
        results=[_Result(Status.PASS), _Result(Status.PARTIAL)],
    )
    json_report = tmp_path / "reports" / "abl-assessment.json"
    html_report = tmp_path / "reports" / "abl-assessment.html"
    json_report.parent.mkdir(parents=True, exist_ok=True)
    json_report.write_text('{"run_id":"abl-assessment"}\n', encoding="utf-8")
    html_report.write_text("<html><body>assessment</body></html>\n", encoding="utf-8")
    monkeypatch.setattr(
        interview_demo,
        "run_assessment",
        lambda *args, **kwargs: (report, json_report, html_report),
    )
    monkeypatch.setattr(
        interview_demo,
        "verify_bundle",
        lambda root: (True, [], {"trace_head_sha256": "trace-head"}),
    )

    observed = {}

    def fake_response(sandbox, output_path, **kwargs):
        observed["response_sandbox"] = sandbox
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
        return SimpleNamespace(
            verified_stopped=True,
            credential_revocation_tested=True,
        )

    monkeypatch.setattr(interview_demo, "run_stop_drill", fake_response)

    def fake_link(assessment_root, response_path, link_path, **kwargs):
        observed["link_sandbox"] = kwargs["expected_sandbox"]
        path = Path(link_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
        return {}

    monkeypatch.setattr(interview_demo, "create_response_link", fake_link)
    monkeypatch.setattr(
        interview_demo,
        "verify_response_link",
        lambda *args, **kwargs: (True, [], {}),
    )
    monkeypatch.setattr(
        interview_demo,
        "cleanup_sandbox",
        lambda name: SimpleNamespace(ok=True),
    )

    summary = interview_demo.run_interview_demo(
        "examples/agent.yaml",
        "examples/task.md",
        output_root=tmp_path,
        cleanup=True,
    )

    assert observed["response_sandbox"] == "abl-demo-real123"
    assert observed["link_sandbox"] == "abl-demo-real123"
    assert summary.response_link_verified is True
    assert summary.sandbox_stop_verified is True
    assert summary.credential_binding_revocation_verified is True
    assert summary.quarantine_registered is True
    assert summary.incident_bundle_verified is True
    assert summary.cleanup_succeeded is True
    assert Path(tmp_path / "reports" / "abl-assessment.interview-demo.json").exists()


def test_interview_demo_dry_run_never_creates_response_link(tmp_path: Path, monkeypatch):
    session_dir = tmp_path / "agent-runs" / "agent-dry"
    session_dir.mkdir(parents=True)
    config = session_dir / "assessment-config.yaml"
    config.write_text("schema_version: 1\n", encoding="utf-8")
    live = SimpleNamespace(
        session_id="agent-dry",
        session_dir=str(session_dir),
        sandbox_name="abl-demo-dry123",
        workspace=str(tmp_path / "workspace"),
        executed=False,
        returncode=None,
        config_for_assessment=str(config),
    )
    monkeypatch.setattr(interview_demo, "run_agent_task", lambda *args, **kwargs: live)

    evidence = tmp_path / "evidence" / "abl-dry"
    evidence.mkdir(parents=True)
    (evidence / "manifest.sha256.json").write_text("{}\n", encoding="utf-8")
    report = SimpleNamespace(run_id="abl-dry", results=[_Result(Status.MANUAL)])
    monkeypatch.setattr(
        interview_demo,
        "run_assessment",
        lambda *args, **kwargs: (
            report,
            tmp_path / "reports" / "abl-dry.json",
            tmp_path / "reports" / "abl-dry.html",
        ),
    )
    monkeypatch.setattr(interview_demo, "verify_bundle", lambda root: (True, [], {}))
    monkeypatch.setattr(
        interview_demo,
        "run_stop_drill",
        lambda sandbox, output_path, **kwargs: SimpleNamespace(
            verified_stopped=False,
            credential_revocation_tested=False,
        ),
    )

    def must_not_link(*args, **kwargs):
        raise AssertionError("dry run must not create a positive response link")

    monkeypatch.setattr(interview_demo, "create_response_link", must_not_link)

    summary = interview_demo.run_interview_demo(
        "examples/agent.yaml",
        "examples/task.md",
        output_root=tmp_path,
        dry_run=True,
    )
    assert summary.response_link_verified is False
    assert summary.sandbox_stop_verified is False
    assert summary.credential_binding_revocation_verified is False
    assert summary.quarantine_registered is False
    assert summary.incident_bundle_verified is False
