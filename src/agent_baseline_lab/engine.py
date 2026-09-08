from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .audit import load_audit_records, normalized_event_types, normalized_result
from .catalog import CONTROLS
from .config import get_path, load_config
from .evaluators import evaluate
from .evidence import EvidenceStore, sha256_file
from .live_run import load_agent_run
from .models import RunReport
from .privacy import portable_path
from .provenance import write_run_attestation
from .report import write_html_report, write_json_report
from .trace import TraceLedger

TRACE_DEPENDENT_CONTROLS = {"AUT-01", "OBS-01", "OBS-02", "OBS-05", "OBS-06"}


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def run_assessment(config_path: str | Path, output_root: str | Path = ".") -> tuple[RunReport, Path, Path]:
    cfg_path = Path(config_path).resolve()
    cfg = load_config(cfg_path)
    started = utc_now()
    run_id = "abl-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = Path(output_root).resolve()
    evidence_dir = out / "evidence" / run_id
    report_dir = out / "reports"
    store = EvidenceStore(evidence_dir, privacy_root=out)
    trace_path = evidence_dir / "trace" / "events.ndjson"
    trace = TraceLedger(trace_path, run_id, privacy_root=out)
    config_path_ref = portable_path(out, cfg_path)
    source_config_sha256 = sha256_file(cfg_path)

    cfg_ev = store.write_text(
        "inputs/assessment-config.yaml",
        cfg_path.read_text(encoding="utf-8"),
        "Assessment configuration snapshot with project/home path prefixes minimized before persistence.",
    )
    ctx = {
        "run_id": run_id,
        "started_at": started,
        "config_path": config_path_ref,
        "config_sha256": cfg_ev.sha256,
        "source_config_sha256": source_config_sha256,
        "trace": trace,
        "trace_path": trace_path,
    }
    trace.append(
        "assessment.started",
        actor="agent-baseline-evidence-lab",
        action="assess",
        target=str(get_path(cfg, "agent.id", "unknown-agent")),
        task_id=str(get_path(cfg, "assessment.task_id", "")),
        attributes={
            "baseline_version": str(get_path(cfg, "baseline.version", "1.0-draft")),
            "config_sha256": cfg_ev.sha256,
            "source_config_sha256": source_config_sha256,
            "path_minimized": True,
        },
    )

    agent_run_cfg = get_path(cfg, "assessment.agent_run", {})
    if isinstance(agent_run_cfg, dict) and agent_run_cfg.get("path"):
        session, verification = load_agent_run(agent_run_cfg["path"])
        run_ev = store.write_json(
            "observations/agent-run.json",
            {"session": session, "verification": verification},
            "Metadata-only agent execution capsule imported into this assessment.",
        )
        ctx["agent_run"] = session
        ctx["agent_run_verification"] = verification
        ctx["agent_run_evidence"] = run_ev
        execution = session.get("execution", {})
        trace.append(
            "agent.task.started",
            actor=str(session.get("agent", "unknown-agent")),
            action="execute-task",
            target=str(session.get("workspace", "")),
            task_id=str(session.get("task_id", "")),
            result="started",
            attributes={
                "agent_session_id": session.get("session_id"),
                "sandbox": session.get("sandbox_name"),
                "model": session.get("agent"),
                "prompt_sha256": session.get("task", {}).get("sha256"),
                "source": "agent-run-capsule",
            },
        )
        attempted = execution.get("attempted") is True
        trace.append(
            "agent.task.completed",
            actor=str(session.get("agent", "unknown-agent")),
            action="execute-task",
            target=str(session.get("workspace", "")),
            task_id=str(session.get("task_id", "")),
            decision=(
                "accept" if attempted and execution.get("returncode") == 0
                else "reject" if attempted
                else "not-executed"
            ),
            result=(
                "success" if attempted and execution.get("returncode") == 0
                else "failure" if attempted
                else "not-executed"
            ),
            attributes={
                "agent_session_id": session.get("session_id"),
                "sandbox": session.get("sandbox_name"),
                "model": session.get("agent"),
                "returncode": execution.get("returncode"),
                "stdout_sha256": execution.get("stdout_sha256"),
                "stderr_sha256": execution.get("stderr_sha256"),
                "workspace_before_sha256": session.get("workspace_before", {}).get("root_sha256"),
                "workspace_after_sha256": session.get("workspace_after", {}).get("root_sha256"),
                "changed_paths": session.get("changes", {}),
                "source": "agent-run-capsule",
            },
        )

    results_by_id = {}
    for control in CONTROLS:
        if control.id in TRACE_DEPENDENT_CONTROLS:
            continue
        results_by_id[control.id] = evaluate(control.id, cfg, store, ctx)

    trace.append(
        "assessment.probes_completed",
        actor="agent-baseline-evidence-lab",
        action="complete-probes",
        target=str(get_path(cfg, "agent.id", "unknown-agent")),
        task_id=str(get_path(cfg, "assessment.task_id", "")),
        result="completed",
    )

    audit_cfg = get_path(cfg, "assessment.docker_audit", {})
    if isinstance(audit_cfg, dict) and audit_cfg.get("enabled") is True:
        audit_records, audit_summary = load_audit_records(
            audit_cfg.get("path") or None,
            audit_session_id=audit_cfg.get("audit_session_id") or None,
            agent=audit_cfg.get("agent") or None,
            since=audit_cfg.get("since") or None,
            until=audit_cfg.get("until") or None,
            max_records=int(audit_cfg.get("max_records", 2000)),
            redaction_salt=run_id,
        )
        audit_ev = store.write_json(
            "observations/docker-ai-governance-audit.json",
            {"summary": audit_summary.to_dict(), "records": audit_records},
            "Docker AI Governance local audit records after run-scoped pseudonymization of user/org/host fields.",
        )
        for record in audit_records:
            event_types = normalized_event_types(record)
            for event_type in event_types:
                trace.append(
                    event_type,
                    actor=str(record.get("agent") or "docker-ai-governance"),
                    action=str(record.get("action_type", "audit-event")),
                    target=str(record.get("resource_id", "")),
                    decision=str(record.get("decision", "")),
                    result=normalized_result(record),
                    task_id=str(get_path(cfg, "assessment.task_id", "")),
                    attributes={
                        "audit_event_id": record.get("audit_event_id"),
                        "audit_session_id": record.get("audit_session_id"),
                        "category": record.get("category"),
                        "schema_version": record.get("schema_version"),
                        "agent": record.get("agent"),
                        "action_type": record.get("action_type"),
                        "source_timestamp": record.get("timestamp"),
                        "source": "docker-ai-governance-local-audit",
                    },
                )
        ctx["docker_audit_summary"] = audit_summary.to_dict()
        ctx["docker_audit_evidence"] = audit_ev

    for control in CONTROLS:
        if control.id in TRACE_DEPENDENT_CONTROLS:
            results_by_id[control.id] = evaluate(control.id, cfg, store, ctx)

    trace.append(
        "assessment.completed",
        actor="agent-baseline-evidence-lab",
        action="finalize-assessment",
        target=str(get_path(cfg, "agent.id", "unknown-agent")),
        task_id=str(get_path(cfg, "assessment.task_id", "")),
        result="completed",
    )

    completed = utc_now()
    results = [results_by_id[control.id] for control in CONTROLS]
    report = RunReport(
        run_id=run_id,
        started_at=started,
        completed_at=completed,
        baseline_version=str(cfg.get("baseline", {}).get("version", "1.0-draft")),
        config_path=config_path_ref,
        results=results,
        metadata={
            "agent_id": cfg.get("agent", {}).get("id"),
            "sandbox": cfg.get("sandbox", {}).get("name"),
            "config_sha256": cfg_ev.sha256,
            "source_config_sha256": source_config_sha256,
            "path_minimization": "project/home prefixes replaced before evidence persistence",
            "trace_ledger": str(trace_path.relative_to(out)),
            "trace_head_sha256": trace.head_hash,
            "trace_event_count": trace.sequence,
            "docker_audit": ctx.get("docker_audit_summary", {"enabled": False}),
            "agent_run": {
                "session_id": ctx.get("agent_run", {}).get("session_id"),
                "executed": ctx.get("agent_run", {}).get("execution", {}).get("attempted", False),
                "manifest_valid": ctx.get("agent_run_verification", {}).get("manifest_valid"),
            },
        },
    )

    provisional = evidence_dir / "assessment.json"
    provisional.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    manifest = store.finalize_manifest()
    manifest_sha256 = sha256_file(manifest)
    report.metadata["evidence_manifest"] = str(manifest.relative_to(out))
    report.metadata["evidence_manifest_sha256"] = manifest_sha256

    attestation_path = report_dir / f"{run_id}.attestation.json"
    attestation_sha256 = write_run_attestation(
        report,
        manifest_path=manifest,
        context=ctx,
        output_path=attestation_path,
    )
    report.metadata["run_attestation"] = {
        "path": str(attestation_path.relative_to(out)),
        "sha256": attestation_sha256,
        "signed": False,
        "statement_type": "https://in-toto.io/Statement/v1",
    }

    json_path = report_dir / f"{run_id}.json"
    html_path = report_dir / f"{run_id}.html"
    write_json_report(report, json_path)
    write_html_report(report, html_path)
    return report, json_path, html_path
