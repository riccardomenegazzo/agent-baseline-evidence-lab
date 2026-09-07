from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import load_audit_records
from .correlation import correlate_tool_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="abl-mcp-correlate",
        description=(
            "Conservatively correlate Docker AI Governance MCP tool-invocation "
            "evaluations with tool-execution outcomes."
        ),
    )
    parser.add_argument(
        "--path",
        default=None,
        help="Docker audit directory or JSONL file; defaults to Docker's OS-specific local path",
    )
    parser.add_argument("--agent", default=None)
    parser.add_argument("--audit-session-id", default=None)
    parser.add_argument("--max-records", type=int, default=5000)
    parser.add_argument("--max-gap-seconds", type=float, default=30.0)
    parser.add_argument("--output", default=None, help="optional JSON report path")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero when allowed evaluations are unmatched or executions are orphaned",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    records, ingest = load_audit_records(
        args.path or None,
        audit_session_id=args.audit_session_id or None,
        agent=args.agent or None,
        max_records=args.max_records,
        redaction_salt="mcp-correlation",
    )
    report = correlate_tool_events(records, max_gap_seconds=args.max_gap_seconds)
    payload = {
        "ingest": ingest.to_dict(),
        "correlation": report.to_dict(),
        "claims_boundary": (
            "Pairs are heuristic because Docker's public audit record reference documents "
            "audit_event_id per event and audit_session_id per daemon session, but does not "
            "document a per-action ID joining tool_invocation to tool_execution."
        ),
    }
    rendered = json.dumps(payload, indent=2) + "\n"
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        print(f"Wrote {path}")
    else:
        print(rendered, end="")

    gaps = bool(report.unmatched_allowed or report.orphan_executions)
    if args.strict and gaps:
        print("MCP correlation gaps detected.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
