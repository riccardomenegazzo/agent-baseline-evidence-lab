from pathlib import Path

from agent_baseline_lab.catalog import CONTROLS
from agent_baseline_lab.engine import run_assessment


def test_engine_emits_all_35_controls(tmp_path: Path):
    config = Path(__file__).resolve().parents[1] / "examples" / "agent.yaml"
    report, json_path, html_path = run_assessment(config, tmp_path)
    assert len(CONTROLS) == 35
    assert len(report.results) == 35
    assert json_path.exists()
    assert html_path.exists()
    evidence = tmp_path / "evidence" / report.run_id
    assert (evidence / "manifest.sha256.json").exists()
