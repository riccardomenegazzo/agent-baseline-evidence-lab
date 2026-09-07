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
