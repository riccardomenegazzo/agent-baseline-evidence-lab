from __future__ import annotations

from agent_baseline_lab.schema import inspect_payload, migrate_payload


def test_response_v1_migrates_to_v2_without_positive_revocation_claim() -> None:
    payload = {
        "schema_version": 1,
        "drill_id": "response-1",
        "sandbox": "abl-demo",
        "verified_stopped": True,
        "notes": [],
    }
    inspected = inspect_payload(payload)
    assert inspected["artifact_type"] == "response-drill"
    assert inspected["migration_available"] is True
    migrated = migrate_payload(payload)
    assert migrated["schema_version"] == 2
    assert migrated["credential_revocation_tested"] is False
    assert migrated["credential_evidence"] == {}


def test_current_schema_is_not_modified() -> None:
    payload = {
        "schema_version": 1,
        "artifact_type": "behavior-drift-report",
        "drift_detected": False,
    }
    assert migrate_payload(payload) == payload
