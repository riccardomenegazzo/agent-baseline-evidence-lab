from pathlib import Path

from agent_baseline_lab.evidence import EvidenceStore, verify_manifest


def test_evidence_manifest_detects_tampering(tmp_path: Path):
    store = EvidenceStore(tmp_path)
    store.write_json("a.json", {"ok": True})
    store.finalize_manifest()
    ok, errors = verify_manifest(tmp_path)
    assert ok
    assert not errors

    (tmp_path / "a.json").write_text('{"ok": false}\n')
    ok, errors = verify_manifest(tmp_path)
    assert not ok
    assert errors == ["hash mismatch: a.json"]


def test_verify_bundle_checks_trace_anchor_and_external_pin(tmp_path: Path):
    import json

    from agent_baseline_lab.evidence import sha256_file, verify_bundle
    from agent_baseline_lab.trace import TraceLedger

    trace_path = tmp_path / "trace" / "events.ndjson"
    ledger = TraceLedger(trace_path, "run-1")
    ledger.append("start", actor="lab", action="start")
    ledger.append("finish", actor="lab", action="finish", result="completed")
    store = EvidenceStore(tmp_path)
    (tmp_path / "assessment.json").write_text(json.dumps({"metadata": {"trace_head_sha256": ledger.head_hash, "trace_event_count": ledger.sequence}}) + "\n", encoding="utf-8")
    store.finalize_manifest()
    manifest_hash = sha256_file(tmp_path / "manifest.sha256.json")
    ok, errors, summary = verify_bundle(tmp_path, expected_manifest_sha256=manifest_hash, expected_trace_head=ledger.head_hash)
    assert ok
    assert errors == []
    assert summary["external_manifest_anchor_checked"] is True
    assert summary["external_trace_anchor_checked"] is True
    raw = trace_path.read_text(encoding="utf-8")
    trace_path.write_text(raw.replace('"result": "completed"', '"result": "tampered"'), encoding="utf-8")
    ok, errors, _ = verify_bundle(tmp_path, expected_trace_head=ledger.head_hash)
    assert not ok
    assert errors
