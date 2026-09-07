from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .catalog import CONTROLS
from .config import get_path, load_config
from .evidence import EvidenceStore, sha256_file
from .evaluators import evaluate
from .models import RunReport
from .report import write_html_report, write_json_report
from .trace import TraceLedger

TRACE_DEPENDENT_CONTROLS = {"OBS-01", "OBS-02", "OBS-05", "OBS-06"}


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
    store = EvidenceStore(evidence_dir)
    trace_path = evidence_dir / "trace" / "events.ndjson"
    trace = TraceLedger(trace_path, run_id)

    cfg_ev = store.write_text(
        "inputs/assessment-config.yaml",
        cfg_path.read_text(encoding="utf-8"),
        "Exact assessment configuration used for the run.",
    )
    ctx = {
        "run_id": run_id,
        "started_at": started,
        "config_path": str(cfg_path),
        "config_sha256": cfg_ev.sha256,
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

    # Evaluate telemetry/integrity controls only after the rest of the run has produced evidence.
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
        config_path=str(cfg_path),
        results=results,
        metadata={
            "agent_id": cfg.get("agent", {}).get("id"),
            "sandbox": cfg.get("sandbox", {}).get("name"),
            "config_sha256": cfg_ev.sha256,
            "trace_ledger": str(trace_path.relative_to(out)),
            "trace_head_sha256": trace.head_hash,
            "trace_event_count": trace.sequence,
        },
    )

    provisional = evidence_dir / "assessment.json"
    provisional.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    manifest = store.finalize_manifest()
    report.metadata["evidence_manifest"] = str(manifest.relative_to(out))
    report.metadata["evidence_manifest_sha256"] = sha256_file(manifest)
    json_path = report_dir / f"{run_id}.json"
    html_path = report_dir / f"{run_id}.html"
    write_json_report(report, json_path)
    write_html_report(report, html_path)
    return report, json_path, html_path
