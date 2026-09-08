from __future__ import annotations

import argparse
import json

from .customer_trust_flow import run_customer_trust_flow
from .demo_preflight import DemoPreflightSummary, run_demo_preflight


def _print_preflight(summary: DemoPreflightSummary) -> None:
    print("LIVE DEMO PREFLIGHT")
    for check in summary.checks:
        marker = "*" if check.required else " "
        print(f"  {check.status:<4} {marker} {check.name:<24} {check.detail}")
    print(f"  READY: {'yes' if summary.ready else 'no'}")


def _print_summary(summary) -> None:
    print("CUSTOMER TRUST FLOW")
    print(f"  assessment:       {summary.assessment_run_id}")
    print(f"  agent session:    {summary.agent_session_id}")
    print(f"  trusted artifact: {summary.trusted_artifact_status}")
    print(f"  Docker Scout:     {summary.scout_status} ({summary.scout_mode})")
    print(f"  lineage verified: {summary.lineage_verified}")
    print(f"  decision:         {summary.decision}")
    print(f"  overall:          {summary.overall_status}")
    print(f"  handoff:          {summary.handoff_pack}")
    print(f"  handoff SHA-256:  {summary.handoff_pack_sha256}")
    print(f"  handoff signed:   {summary.handoff_signature_verified}")
    print("  next:             run `abl-present --open` to review the demo artifacts")


def _flow_exit_code(summary) -> int:
    if summary.dry_run:
        return 0
    if summary.overall_status == "BLOCKED":
        return 1
    if summary.scout_mode == "gate" and summary.overall_status != "EVIDENCE_READY":
        return 1
    if not summary.lineage_verified or not summary.handoff_verified:
        return 1
    if not summary.handoff_signature_verified:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the customer trust lifecycle with a fail-closed live-demo preflight"
    )
    parser.add_argument("--root", default=".")
    parser.add_argument("--profile", choices=["community", "mcp"], default="community")
    parser.add_argument("--baseline-cache", default=".cache/agentbaseline")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--scout-mode", choices=["off", "observe", "gate"], default="observe")
    parser.add_argument("--no-cleanup", action="store_true")
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="check live-demo prerequisites and exit before creating a sandbox",
    )
    parser.add_argument(
        "--preflight-smoke",
        action="store_true",
        help="include a disposable Docker Sandbox create/exec/policy/remove smoke test",
    )
    parser.add_argument(
        "--preflight-output",
        default="reports/demo-preflight.json",
        help="machine-readable preflight output",
    )
    args = parser.parse_args(argv)

    if args.preflight_only or not args.dry_run:
        try:
            preflight = run_demo_preflight(
                args.root,
                baseline_cache=args.baseline_cache,
                scout_mode=args.scout_mode,
                sandbox_smoke=args.preflight_smoke,
            )
        except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        output = __import__("pathlib").Path(args.preflight_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(preflight.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _print_preflight(preflight)
        if not preflight.ready:
            return 1
        if args.preflight_only:
            return 0

    try:
        summary = run_customer_trust_flow(
            args.root,
            profile=args.profile,
            baseline_cache=args.baseline_cache,
            dry_run=args.dry_run,
            scout_mode=args.scout_mode,
            cleanup=not args.no_cleanup,
        )
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    _print_summary(summary)
    return _flow_exit_code(summary)


if __name__ == "__main__":
    raise SystemExit(main())
