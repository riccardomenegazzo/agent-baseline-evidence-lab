import json

from agent_baseline_lab.response import _find_sandbox_status, load_response_drill, run_stop_drill


def test_find_sandbox_status_nested_payload():
    payload = {"sandboxes": [{"name": "other", "status": "running"}, {"name": "abl-demo", "state": "stopped"}]}
    assert _find_sandbox_status(payload, "abl-demo") == "stopped"


def test_dry_run_writes_non_claiming_evidence(tmp_path):
    path = tmp_path / "response.json"
    result = run_stop_drill("abl-demo", path, dry_run=True)
    assert result.verified_stopped is False
    assert result.credential_revocation_tested is False
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["sandbox"] == "abl-demo"
    loaded, errors = load_response_drill(path, expected_sandbox="abl-demo")
    assert errors == []
    assert loaded is not None
    assert loaded["verified_stopped"] is False


def test_response_evidence_rejects_sandbox_mismatch(tmp_path):
    path = tmp_path / "response.json"
    run_stop_drill("abl-demo", path, dry_run=True)
    _, errors = load_response_drill(path, expected_sandbox="customer-prod")
    assert errors
