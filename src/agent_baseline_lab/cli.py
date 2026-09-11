from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter
from pathlib import Path

from .audit import default_audit_dir, load_audit_records
from .baseline import DEFAULT_URL, sync
from .catalog import CONTROL_BY_ID, OUTCOME_NAMES
from .config import ConfigError
from .engine import run_assessment
from .evidence import verify_bundle
from .live_run import cleanup_sandbox, run_agent_task
from .models import Status
from .provenance import verify_run_attestation
from .workspace import initialize_workspace


ANSI = {
    Status.PASS: "\033[32m",
    Status.FAIL: "\033[31m",
    Status.PARTIAL: "\033[33m",
    Status.MANUAL: "\033[90m",
    Status.NOT_APPLICABLE: "\033[36m",
    Status.ERROR: "\033[31;1m",
}
RESET = "\033[0m"


def _color(status: Status, text: str) -> str:
    if not sys.stdout.isatty() or "NO_COLOR" in __import__("os").environ:
        return text
    return f"{ANSI[status]}{text}{RESET}"


def print_report(report) -> None:
    print("\nAGENT BASELINE EVIDENCE LAB")
    print(f"Run: {report.run_id}   Baseline: {report.baseline_version}")
    print("-" * 78)
    current = None
    for result in report.results:
        control = CONTROL_BY_ID[result.control_id]
        if control.outcome != current:
            current = control.outcome
            print(f"\n{current}  {OUTCOME_NAMES[current]}")
        label = _color(result.status, f"{result.status.value:>7}")
        print(f"  {control.id:<7} {label}  {control.title}")
    counts = Counter(r.status for r in report.results)
    print("\n" + "-" * 78)
    print("  ".join(f"{s.value}={counts[s]}" for s in Status))


def _print_report_paths(report, json_path: Path, html_path: Path, output_root: str) -> None:
    print(f"\nJSON report: {json_path}")
    print(f"HTML report: {html_path}")
    print(f"Evidence:    {Path(output_root).resolve() / 'evidence' / report.run_id}")
    attestation = report.metadata.get("run_attestation", {})
    if isinstance(attestation, dict) and attestation.get("path"):
        print(f"Attestation: {Path(output_root).resolve() / str(attestation['path'])}")
        print(f"Attest SHA:  {attestation.get('sha256', '')}")


def cmd_init(args) -> int:
    try:
        root = initialize_workspace(args.destination)
    except (OSError, ValueError) as exc:
        print(f"workspace initialization failed: {exc}", file=sys.stderr)
        return 2
    print(f"Workspace created: {root}")
    print("Change to that directory, then run:")
    print("  abl-trust --dry-run --scout-mode off")
    print("  abl-present --open")
    print("Expected: DRY_RUN, no live artifact or lineage claim.")
    return 0


def cmd_assess(args) -> int:
    try:
        report, json_path, html_path = run_assessment(args.config, args.output)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    print_report(report)
    _print_report_paths(report, json_path, html_path, args.output)
    return 1 if any(r.status in (Status.FAIL, Status.ERROR) for r in report.results) else 0


def cmd_preflight(args) -> int:
    rows = []
    for binary in ("python3", "sbx", "docker"):
        path = shutil.which(binary)
        rows.append((binary, bool(path), path or "not found"))
    print("PRE-FLIGHT")
    for name, ok, detail in rows:
        print(f"  {'OK' if ok else '--':>2}  {name:<8} {detail}")
    print("\nNote: `sbx` is required for live sandbox evidence. Docker AI Governance audit ingestion is optional and requires local audit delivery.")
    print(f"Default Docker audit path for this OS: {default_audit_dir()}")
    return 0


def cmd_sync(args) -> int:
    try:
        lock = sync(args.url, Path(args.cache))
    except Exception as exc:
        print(f"baseline sync failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(lock, indent=2))
    if lock["drift"]["missing_from_upstream"] or lock["drift"]["new_upstream_ids"]:
        print("WARNING: upstream control-ID drift detected.", file=sys.stderr)
        return 1
    return 0


def cmd_verify(args) -> int:
    root = Path(args.evidence_dir)
    ok, errors, summary = verify_bundle(
        root,
        expected_manifest_sha256=args.expected_manifest_sha256,
        expected_trace_head=args.expected_trace_head,
    )
    if ok:
        print("Evidence bundle verified.")
    else:
        for error in errors:
            print(error, file=sys.stderr)
    print(json.dumps(summary, indent=2))
    if not args.expected_manifest_sha256 and not args.expected_trace_head:
        print("Note: no external hash anchor was supplied; this verifies internal consistency, not a digital signature.")
    return 0 if ok else 1


def cmd_verify_attestation(args) -> int:
    ok, errors, summary = verify_run_attestation(
        Path(args.attestation),
        Path(args.manifest),
        expected_attestation_sha256=args.expected_attestation_sha256,
    )
    if ok:
        print("Run attestation verified against evidence manifest.")
    else:
        for error in errors:
            print(error, file=sys.stderr)
    print(json.dumps(summary, indent=2))
    if not args.expected_attestation_sha256:
        print("Note: no external attestation hash was supplied; authenticity is not established.")
    return 0 if ok else 1


def cmd_audit_summary(args) -> int:
    records, summary = load_audit_records(
        args.path or None,
        audit_session_id=args.audit_session_id or None,
        agent=args.agent or None,
        max_records=args.max_records,
        redaction_salt="audit-summary",
    )
    data = summary.to_dict()
    data["sample_event_ids"] = [str(r.get("audit_event_id", "")) for r in records[-5:]]
    print(json.dumps(data, indent=2))
    return 0


def cmd_live_run(args) -> int:
    try:
        live = run_agent_task(
            args.config,
            args.task,
            output_root=args.output,
            timeout=args.timeout,
            dry_run=args.dry_run,
            capture_output=args.capture_output,
            enable_audit=args.with_docker_audit,
        )
    except (ConfigError, ValueError) as exc:
        print(f"live-run configuration error: {exc}", file=sys.stderr)
        return 2

    print("AGENT RUN CAPSULE")
    print(f"  session:   {live.session_id}")
    print(f"  sandbox:   {live.sandbox_name}")
    print(f"  workspace: {live.workspace}")
    print(f"  evidence:  {live.session_dir}")
    print(f"  executed:  {live.executed}")
    if live.returncode is not None:
        print(f"  returncode:{live.returncode}")

    assessment_rc = 0
    if args.assess:
        try:
            report, json_path, html_path = run_assessment(
                live.config_for_assessment,
                args.output,
            )
        except ConfigError as exc:
            print(f"assessment configuration error: {exc}", file=sys.stderr)
            assessment_rc = 2
        else:
            print_report(report)
            _print_report_paths(report, json_path, html_path, args.output)
            assessment_rc = (
                1
                if any(r.status in (Status.FAIL, Status.ERROR) for r in report.results)
                else 0
            )

    if live.executed and not args.keep_sandbox:
        cleanup = cleanup_sandbox(live.sandbox_name)
        if not cleanup.ok:
            print(
                f"warning: failed to remove sandbox {live.sandbox_name}: {cleanup.stderr}",
                file=sys.stderr,
            )

    if live.executed and live.returncode not in (None, 0):
        return 1
    return assessment_rc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="abl", description="Agent Baseline Evidence Lab")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create a standalone workspace with example assets and local keys")
    init.add_argument("destination", help="new directory to create (must not already exist)")
    init.set_defaults(func=cmd_init)

    assess = sub.add_parser("assess", help="run an assessment")
    assess.add_argument("--config", default="examples/agent.yaml")
    assess.add_argument("--output", default=".")
    assess.set_defaults(func=cmd_assess)

    preflight = sub.add_parser("preflight", help="check local prerequisites")
    preflight.set_defaults(func=cmd_preflight)

    sync_p = sub.add_parser("sync-baseline", help="fetch and hash the authoritative upstream controls file")
    sync_p.add_argument("--url", default=DEFAULT_URL)
    sync_p.add_argument("--cache", default=".cache/agentbaseline")
    sync_p.set_defaults(func=cmd_sync)

    verify = sub.add_parser("verify", help="verify an evidence bundle")
    verify.add_argument("evidence_dir")
    verify.add_argument("--expected-manifest-sha256", default=None, help="optional externally pinned manifest hash")
    verify.add_argument("--expected-trace-head", default=None, help="optional externally pinned trace head hash")
    verify.set_defaults(func=cmd_verify)

    verify_att = sub.add_parser(
        "verify-attestation",
        help="verify a run attestation against its evidence manifest",
    )
    verify_att.add_argument("attestation")
    verify_att.add_argument("manifest")
    verify_att.add_argument(
        "--expected-attestation-sha256",
        default=None,
        help="optional externally pinned attestation hash",
    )
    verify_att.set_defaults(func=cmd_verify_attestation)

    audit = sub.add_parser(
        "audit-summary",
        help="summarize Docker AI Governance local JSONL audit records without raw identity fields",
    )
    audit.add_argument(
        "--path",
        default=None,
        help="audit directory or .jsonl file; defaults to Docker's OS-specific local path",
    )
    audit.add_argument("--audit-session-id", default=None)
    audit.add_argument("--agent", default=None)
    audit.add_argument("--max-records", type=int, default=2000)
    audit.set_defaults(func=cmd_audit_summary)

    live = sub.add_parser(
        "live-run",
        help="run a real coding-agent task in a disposable Docker Sandbox workspace",
    )
    live.add_argument("--config", default="examples/agent.yaml")
    live.add_argument("--task", default="examples/task.md")
    live.add_argument("--output", default=".")
    live.add_argument("--timeout", type=int, default=900)
    live.add_argument("--assess", action="store_true", help="assess the live workspace before cleanup")
    live.add_argument("--dry-run", action="store_true", help="build and verify the capsule without invoking sbx")
    live.add_argument(
        "--capture-output",
        action="store_true",
        help="persist raw agent stdout/stderr; off by default for data minimization",
    )
    live.add_argument(
        "--with-docker-audit",
        action="store_true",
        help="ingest finalized local Docker AI Governance audit records in the run time window",
    )
    live.add_argument("--keep-sandbox", action="store_true")
    live.set_defaults(func=cmd_live_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

