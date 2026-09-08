from __future__ import annotations

import json
from pathlib import Path

from agent_baseline_lab.drift import build_profile, compare_profile


def _write_trace(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(item) + "\n" for item in events), encoding="utf-8")


def test_behavior_profile_detects_new_destination_and_tool(tmp_path: Path) -> None:
    baseline_trace = tmp_path / "baseline.ndjson"
    current_trace = tmp_path / "current.ndjson"
    _write_trace(
        baseline_trace,
        [
            {"event_type": "network.egress", "target": "api.openai.com", "attributes": {}},
            {"event_type": "mcp.tool", "target": "dhi/search", "attributes": {}},
        ],
    )
    _write_trace(
        current_trace,
        [
            {"event_type": "network.egress", "target": "api.openai.com", "attributes": {}},
            {"event_type": "network.egress", "target": "example.invalid", "attributes": {}},
            {"event_type": "mcp.tool", "target": "dhi/search", "attributes": {}},
            {"event_type": "mcp.tool", "target": "dhi/inspect", "attributes": {}},
        ],
    )
    profile = build_profile(baseline_trace, profile_id="known-good")
    result = compare_profile(profile, current_trace)
    assert result.drift_detected is True
    assert result.new_destinations == ["example.invalid"]
    assert result.new_mcp_tools == ["dhi/inspect"]


def test_identical_trace_has_no_drift(tmp_path: Path) -> None:
    trace = tmp_path / "trace.ndjson"
    _write_trace(trace, [{"event_type": "mcp.tool", "target": "dhi/search", "attributes": {}}])
    profile = build_profile(trace)
    result = compare_profile(profile, trace)
    assert result.drift_detected is False
