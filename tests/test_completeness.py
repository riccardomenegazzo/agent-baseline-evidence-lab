import json
from pathlib import Path

import pytest

from agent_baseline_lab.completeness import (
    load_witness,
    make_witness,
    reconcile_event_ids,
    reconcile_files,
)


def test_reconcile_event_ids_detects_missing_expected_event():
    witness = make_witness(
        "witness-1",
        "task-1",
        "independent-source",
        ["event-a", "event-b", "event-c"],
    )
    result = reconcile_event_ids(
        witness,
        ["event-a", "event-c"],
        witness_sha256="a" * 64,
        observed_sha256="b" * 64,
    )
    assert result.completeness_verified is False
    assert result.missing_event_ids == ["event-b"]
    assert result.matched_count == 2


def test_reconcile_event_ids_accepts_complete_unique_set():
    witness = make_witness(
        "witness-1",
        "task-1",
        "independent-source",
        ["event-a", "event-b"],
    )
    result = reconcile_event_ids(
        witness,
        ["event-b", "event-a"],
        witness_sha256="a" * 64,
        observed_sha256="b" * 64,
    )
    assert result.completeness_verified is True
    assert result.missing_event_ids == []
    assert result.duplicate_observed_event_ids == []


def test_reconcile_event_ids_rejects_duplicate_observed_ids():
    witness = make_witness(
        "witness-1",
        "task-1",
        "independent-source",
        ["event-a"],
    )
    result = reconcile_event_ids(
        witness,
        ["event-a", "event-a"],
        witness_sha256="a" * 64,
        observed_sha256="b" * 64,
    )
    assert result.completeness_verified is False
    assert result.duplicate_observed_event_ids == ["event-a"]


def test_reconcile_files_persists_digests_and_result(tmp_path: Path):
    witness_path = tmp_path / "witness.json"
    witness = make_witness(
        "witness-1",
        "task-1",
        "external-audit",
        ["event-a", "event-b"],
        checkpoint="checkpoint-123",
    )
    witness_path.write_text(
        json.dumps(witness.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )
    observed_path = tmp_path / "observed.json"
    observed_path.write_text(
        json.dumps({"observed_event_ids": ["event-a", "event-b"]}) + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "result.json"
    result = reconcile_files(witness_path, observed_path, output_path=output)
    assert result.completeness_verified is True
    assert result.checkpoint == "checkpoint-123"
    assert len(result.witness_sha256) == 64
    assert len(result.observed_sha256) == 64
    assert output.exists()


def test_load_witness_rejects_duplicate_expectations(tmp_path: Path):
    path = tmp_path / "witness.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "witness_id": "w1",
                "scope": "task-1",
                "source": "source",
                "expected_event_ids": ["event-a", "event-a"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_witness(path)
