from __future__ import annotations

import json
from pathlib import Path

from agent_baseline_lab.incident_bundle import create_incident_bundle, verify_incident_bundle
from agent_baseline_lab.quarantine import create_quarantine_entry, verify_registry


def test_quarantine_registry_and_incident_bundle_detect_mutation(tmp_path: Path) -> None:
    response = tmp_path / "response.json"
    response.write_text(json.dumps({"verified_stopped": True}) + "\n", encoding="utf-8")
    registry = tmp_path / "registry.ndjson"

    entry = create_quarantine_entry(
        registry,
        component_type="sandbox",
        component_id="abl-demo",
        reason="response drill containment",
        source_run_id="abl-test",
        response_evidence_path=response,
    )
    assert entry.state == "quarantined"
    registry_ok, registry_errors, registry_summary = verify_registry(registry)
    assert registry_ok is True
    assert registry_errors == []
    assert registry_summary["entry_count"] == 1

    assessment = tmp_path / "assessment.json"
    assessment.write_text(json.dumps({"run_id": "abl-test"}) + "\n", encoding="utf-8")
    incident = tmp_path / "incident.json"
    create_incident_bundle(
        incident,
        source_run_id="abl-test",
        artifacts=[("assessment", assessment), ("response", response), ("quarantine-registry", registry)],
    )
    incident_ok, incident_errors, summary = verify_incident_bundle(incident)
    assert incident_ok is True
    assert incident_errors == []
    assert summary["verified_artifact_count"] == 3

    response.write_text(json.dumps({"verified_stopped": False}) + "\n", encoding="utf-8")
    mutated_ok, mutated_errors, _ = verify_incident_bundle(incident)
    assert mutated_ok is False
    assert any("digest mismatch" in error for error in mutated_errors)
