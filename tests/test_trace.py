import json
from pathlib import Path

from agent_baseline_lab.trace import TraceLedger, verify_trace


def test_trace_hash_chain_detects_mutation(tmp_path: Path):
    path = tmp_path / "events.ndjson"
    ledger = TraceLedger(path, "run-1")
    ledger.append("start", actor="lab", action="start", task_id="task-1")
    ledger.append("decision", actor="lab", action="network", target="example.com", decision="deny")
    ok, errors = verify_trace(path)
    assert ok
    assert errors == []
    raw = path.read_text(encoding="utf-8")
    path.write_text(raw.replace('"decision": "deny"', '"decision": "allow"', 1), encoding="utf-8")
    ok, errors = verify_trace(path)
    assert not ok
    assert any("event_hash mismatch" in error for error in errors)


def test_trace_minimizes_local_paths_before_hashing(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    workspace = project / ".abl-workspaces" / "agent-1" / "workspace"
    path = project / "events.ndjson"
    ledger = TraceLedger(path, "run-privacy", privacy_root=project)

    record = ledger.append(
        "agent.task.completed",
        actor="codex",
        action="execute-task",
        target=str(workspace),
        attributes={
            "workspace": str(workspace),
            "nested": {"path": str(project / "reports" / "result.json")},
        },
    )

    raw = path.read_text(encoding="utf-8")
    assert str(project) not in raw
    assert record["target"].startswith("<project>/")
    assert record["attributes"]["workspace"].startswith("<project>/")
    assert record["attributes"]["nested"]["path"] == "<project>/reports/result.json"
    ok, errors = verify_trace(path)
    assert ok, errors
    persisted = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert persisted["event_hash"] == record["event_hash"]
