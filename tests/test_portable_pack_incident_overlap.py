from __future__ import annotations

import json
import zipfile
from pathlib import Path

from agent_baseline_lab import portable_pack


def test_incident_reference_reuses_existing_evidence_member(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "project"
    run_id = "abl-test"
    evidence = root / "evidence" / run_id
    evidence.mkdir(parents=True)
    manifest = evidence / "manifest.sha256.json"
    manifest.write_text('{"schema_version":1}\n', encoding="utf-8")

    reports = root / "reports"
    reports.mkdir()
    incident = reports / f"{run_id}.incident.json"
    incident.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_run_id": run_id,
                "artifacts": [
                    {
                        "role": "assessment-manifest",
                        "path": str(manifest.resolve()),
                        "sha256": portable_pack.sha256_file(manifest),
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        portable_pack,
        "verify_bundle",
        lambda path: (
            True,
            [],
            {
                "manifest_sha256": "manifest",
                "trace_head_sha256": "trace-head",
                "trace_event_count": 1,
            },
        ),
    )

    pack_path, summary = portable_pack.create_pack(
        root,
        output_path=reports / "customer-evidence-pack.zip",
        run_id=run_id,
    )
    ok, errors, _ = portable_pack.verify_pack(pack_path)

    assert ok is True, errors
    archive_path = f"evidence/{run_id}/manifest.sha256.json"
    assert summary.linked_incident_artifacts[0].archive_path == archive_path
    assert summary.linked_incident_artifacts[0].role == "assessment-manifest"

    with zipfile.ZipFile(pack_path, "r") as zf:
        assert zf.namelist().count(archive_path) == 1
