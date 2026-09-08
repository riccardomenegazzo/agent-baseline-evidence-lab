from __future__ import annotations

import pytest

from agent_baseline_lab.schemas import SchemaMigrationError, migrate_payload


def test_response_v1_to_v2_is_fail_closed() -> None:
    migrated = migrate_payload(
        "response-drill",
        {
            "schema_version": 1,
            "sandbox": "abl-demo",
            "verified_stopped": True,
        },
    )
    assert migrated["schema_version"] == 2
    assert migrated["verified_stopped"] is True
    assert migrated["credential_revocation_tested"] is False
    assert migrated["credential_revocation_scope"] is None
    assert migrated["credential_evidence"] == {}


def test_interview_v1_to_v3_is_fail_closed() -> None:
    migrated = migrate_payload(
        "interview-demo",
        {
            "schema_version": 1,
            "response_link_verified": True,
        },
    )
    assert migrated["schema_version"] == 3
    assert migrated["response_link_verified"] is True
    assert migrated["audit_correlation_exact_marker"] is False
    assert migrated["quarantine_registered"] is False
    assert migrated["incident_bundle_verified"] is False


def test_future_schema_fails_closed() -> None:
    with pytest.raises(SchemaMigrationError):
        migrate_payload("response-drill", {"schema_version": 99})
