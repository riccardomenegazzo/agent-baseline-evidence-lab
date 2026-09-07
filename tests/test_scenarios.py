from pathlib import Path

from agent_baseline_lab.evidence import EvidenceStore
from agent_baseline_lab.scenarios import run_scenarios


def test_mcp_policy_contract_executes_offline(tmp_path: Path):
    policy = Path(__file__).resolve().parents[1] / "policies" / "mcp" / "strict-reference.cedar"
    cfg = {"assessment": {"adversarial_scenarios": [{"id": "mcp-contract", "type": "mcp-policy-contract", "policy_file": str(policy), "require": ["no_actionless_permit", "registration_identity_binding", "tool_scope", "approval_guard", "local_stdio_forbid"]}]}}
    results, evidence = run_scenarios(cfg, EvidenceStore(tmp_path), {"run_id": "run-1", "task_id": "task-1"})
    assert results[0]["status"] == "PASS"
    assert evidence.path == "controls/VAL-01/scenario-results.json"
