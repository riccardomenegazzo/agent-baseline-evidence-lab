from pathlib import Path

from agent_baseline_lab.evidence import EvidenceStore
from agent_baseline_lab.evaluators import evaluate
from agent_baseline_lab.models import Status


def test_toxic_capability_detector_fails_on_three_way_combo(tmp_path: Path):
    cfg = {"agent": {"capabilities": [{"kind": "untrusted_input"}, {"kind": "sensitive_data"}, {"kind": "external_write"}]}}
    result = evaluate("CON-02", cfg, EvidenceStore(tmp_path), {"run_id": "x", "started_at": "now"})
    assert result.status == Status.FAIL
