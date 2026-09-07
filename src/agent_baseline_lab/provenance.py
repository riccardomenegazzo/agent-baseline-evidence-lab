from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .evidence import sha256_file
from .models import RunReport

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = (
    "https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/attestation/v1"
)


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_run_attestation(
    report: RunReport,
    *,
    manifest_path: Path,
    context: dict[str, Any],
) -> dict[str, Any]:
    """Build an unsigned in-toto-style statement for one assessment run.

    This binds the evidence manifest to the task/runtime facts observed by the lab.
    It is intentionally unsigned: authenticity requires an external signer or trust anchor.
    """
    agent_run = context.get("agent_run", {}) or {}
    task = agent_run.get("task", {}) or {}
    execution = agent_run.get("execution", {}) or {}
    before = agent_run.get("workspace_before", {}) or {}
    after = agent_run.get("workspace_after", {}) or {}
    changes = agent_run.get("changes", {}) or {}
    status_counts = Counter(result.status.value for result in report.results)
    result_vector = [
        {"control_id": result.control_id, "status": result.status.value}
        for result in report.results
    ]

    predicate: dict[str, Any] = {
        "schemaVersion": 1,
        "claimBoundary": "implementation evidence; not certification or official conformance",
        "assessment": {
            "runId": report.run_id,
            "baselineVersion": report.baseline_version,
            "startedAt": report.started_at,
            "completedAt": report.completed_at,
            "configSha256": report.metadata.get("config_sha256"),
            "traceHeadSha256": report.metadata.get("trace_head_sha256"),
            "traceEventCount": report.metadata.get("trace_event_count"),
            "controlStatusCounts": dict(sorted(status_counts.items())),
            "controlResultVectorSha256": _sha256_json(result_vector),
        },
        "agentRun": {
            "sessionId": agent_run.get("session_id"),
            "agent": agent_run.get("agent"),
            "sandbox": agent_run.get("sandbox_name"),
            "taskSha256": task.get("sha256"),
            "taskBytes": task.get("bytes"),
            "promptPersisted": task.get("persisted", False),
            "executed": execution.get("attempted", False),
            "returncode": execution.get("returncode"),
            "stdoutSha256": execution.get("stdout_sha256"),
            "stderrSha256": execution.get("stderr_sha256"),
            "workspaceBeforeSha256": before.get("root_sha256"),
            "workspaceAfterSha256": after.get("root_sha256"),
            "changesSha256": _sha256_json(changes) if changes else None,
        },
        "dockerAudit": report.metadata.get("docker_audit", {"enabled": False}),
        "integrity": {
            "manifestAlgorithm": "sha256",
            "manifestSha256": sha256_file(manifest_path),
            "signed": False,
            "externalTrustAnchorRequiredForAuthenticity": True,
        },
    }

    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": manifest_path.name,
                "digest": {"sha256": sha256_file(manifest_path)},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def write_run_attestation(
    report: RunReport,
    *,
    manifest_path: Path,
    context: dict[str, Any],
    output_path: Path,
) -> str:
    statement = build_run_attestation(report, manifest_path=manifest_path, context=context)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return sha256_file(output_path)


def verify_run_attestation(
    attestation_path: Path,
    manifest_path: Path,
    *,
    expected_attestation_sha256: str | None = None,
) -> tuple[bool, list[str], dict[str, Any]]:
    """Verify statement shape and that its subject still matches the evidence manifest.

    An optional expected attestation hash turns this into an externally anchored check.
    Without it, this verifies statement consistency only; the statement is intentionally unsigned.
    """
    errors: list[str] = []
    try:
        statement = json.loads(attestation_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, [f"attestation cannot be parsed: {exc}"], {}

    if statement.get("_type") != STATEMENT_TYPE:
        errors.append("unexpected statement type")
    if statement.get("predicateType") != PREDICATE_TYPE:
        errors.append("unexpected predicate type")

    subjects = statement.get("subject", [])
    recorded_manifest_hash = ""
    if not isinstance(subjects, list) or len(subjects) != 1:
        errors.append("attestation must contain exactly one evidence-manifest subject")
    else:
        subject = subjects[0] if isinstance(subjects[0], dict) else {}
        digest = subject.get("digest", {}) if isinstance(subject, dict) else {}
        recorded_manifest_hash = str(digest.get("sha256", ""))

    observed_manifest_hash = sha256_file(manifest_path) if manifest_path.exists() else ""
    if not observed_manifest_hash:
        errors.append("evidence manifest is missing")
    elif recorded_manifest_hash != observed_manifest_hash:
        errors.append("attestation subject digest does not match evidence manifest")

    observed_attestation_hash = sha256_file(attestation_path) if attestation_path.exists() else ""
    if expected_attestation_sha256 and observed_attestation_hash != expected_attestation_sha256:
        errors.append("attestation hash does not match external expected value")

    predicate = statement.get("predicate", {}) if isinstance(statement, dict) else {}
    integrity = predicate.get("integrity", {}) if isinstance(predicate, dict) else {}
    if integrity.get("signed") is not False:
        errors.append("unexpected signed claim; this attestation format is currently unsigned")

    summary = {
        "manifest_sha256": observed_manifest_hash,
        "attestation_sha256": observed_attestation_hash,
        "subject_matches_manifest": recorded_manifest_hash == observed_manifest_hash,
        "external_attestation_anchor_checked": bool(expected_attestation_sha256),
        "signed": False,
    }
    return not errors, errors, summary
