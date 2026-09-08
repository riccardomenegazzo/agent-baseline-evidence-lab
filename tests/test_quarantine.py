from __future__ import annotations

from pathlib import Path

from agent_baseline_lab.quarantine import append_event, current_states


def test_quarantine_and_release_are_append_only(tmp_path: Path) -> None:
    registry = tmp_path / "quarantine.json"
    evidence = tmp_path / "evidence.json"
    evidence.write_text("evidence\n", encoding="utf-8")
    append_event(
        registry,
        component_id="sandbox-1",
        component_type="sandbox",
        action="quarantine",
        reason="response drill",
        actor="tester",
        source_evidence=evidence,
    )
    assert current_states(registry)["sandbox-1"]["state"] == "quarantined"
    append_event(
        registry,
        component_id="sandbox-1",
        component_type="sandbox",
        action="release",
        reason="review complete",
        actor="tester",
        source_evidence=evidence,
    )
    state = current_states(registry)["sandbox-1"]
    assert state["state"] == "released"
    assert registry.read_text(encoding="utf-8").count('"event_id"') == 2
