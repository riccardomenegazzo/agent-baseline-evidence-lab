from pathlib import Path

from agent_baseline_lab.evidence import EvidenceStore, sha256_file
from agent_baseline_lab.models import Result, RunReport, Status
from agent_baseline_lab.provenance import (
    build_run_attestation,
    verify_run_attestation,
    write_run_attestation,
)


def _report() -> RunReport:
    return RunReport(
        run_id="abl-test",
        started_at="2026-09-08T00:00:00+00:00",
        completed_at="2026-09-08T00:00:01+00:00",
        baseline_version="1.0-draft",
        config_path="examples/agent.yaml",
        results=[Result("DIS-01", Status.PASS, "ok")],
        metadata={
            "config_sha256": "c" * 64,
            "trace_head_sha256": "t" * 64,
            "trace_event_count": 3,
            "docker_audit": {"enabled": False},
        },
    )


def _context() -> dict:
    return {
        "agent_run": {
            "session_id": "agent-1",
            "agent": "codex",
            "sandbox_name": "abl-demo-1",
            "task": {"sha256": "a" * 64, "bytes": 42, "persisted": False},
            "execution": {
                "attempted": True,
                "returncode": 0,
                "stdout_sha256": "b" * 64,
                "stderr_sha256": "d" * 64,
            },
            "workspace_before": {"root_sha256": "e" * 64},
            "workspace_after": {"root_sha256": "f" * 64},
            "changes": {"added": ["health.py"], "removed": [], "modified": []},
        }
    }


def test_attestation_binds_manifest_and_agent_run(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    store = EvidenceStore(evidence)
    store.write_json("observation.json", {"ok": True})
    manifest = store.finalize_manifest()

    statement = build_run_attestation(_report(), manifest_path=manifest, context=_context())

    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["subject"][0]["name"] == "manifest.sha256.json"
    assert len(statement["subject"][0]["digest"]["sha256"]) == 64
    predicate = statement["predicate"]
    assert predicate["assessment"]["runId"] == "abl-test"
    assert predicate["agentRun"]["agent"] == "codex"
    assert predicate["agentRun"]["taskSha256"] == "a" * 64
    assert predicate["agentRun"]["promptPersisted"] is False
    assert predicate["integrity"]["signed"] is False
    assert predicate["integrity"]["externalTrustAnchorRequiredForAuthenticity"] is True


def test_attestation_verifier_detects_manifest_mutation(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    store = EvidenceStore(evidence)
    store.write_json("observation.json", {"ok": True})
    manifest = store.finalize_manifest()
    attestation = tmp_path / "run.attestation.json"
    attestation_hash = write_run_attestation(
        _report(), manifest_path=manifest, context=_context(), output_path=attestation
    )

    ok, errors, summary = verify_run_attestation(
        attestation,
        manifest,
        expected_attestation_sha256=attestation_hash,
    )
    assert ok is True
    assert errors == []
    assert summary["external_attestation_anchor_checked"] is True

    manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    ok, errors, _ = verify_run_attestation(attestation, manifest)
    assert ok is False
    assert "attestation subject digest does not match evidence manifest" in errors
    assert sha256_file(attestation) == attestation_hash
