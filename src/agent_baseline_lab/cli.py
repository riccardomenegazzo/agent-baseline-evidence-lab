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
from .models import Status


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


def cmd_assess(args) -> int:
    try:
        report, json_path, html_path = run_assessment(args.config, args.output)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    print_report(report)
    print(f"\nJSON report: {json_path}")
    print(f"HTML report: {html_path}")
    print(f"Evidence:    {Path(args.output).resolve() / 'evidence' / report.run_id}")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="abl", description="Agent Baseline Evidence Lab")
    sub = parser.add_subparsers(dest="command", required=True)

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

    audit = sub.add_parser("audit-summary", help="summarize Docker AI Governance local JSONL audit records without persisting raw identity fields")
    audit.add_argument("--path", default=None, help="audit directory or .jsonl file; defaults to Docker's OS-specific local path")
    audit.add_argument("--audit-session-id", default=None)
    audit.add_argument("--agent", default=None)
    audit.add_argument("--max-records", type=int, default=2000)
    audit.set_defaults(func=cmd_audit_summary)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
