from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .evidence import sha256_file
from .trace import read_trace


@dataclass(frozen=True)
class BehavioralBaseline:
    schema_version: int
    event_type_counts: dict[str, int]
    network_destinations: list[str]
    mcp_targets: list[str]
    source_trace_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DriftResult:
    schema_version: int
    new_network_destinations: list[str]
    missing_network_destinations: list[str]
    new_mcp_targets: list[str]
    missing_mcp_targets: list[str]
    event_type_count_deltas: dict[str, int]
    drift_detected: bool
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_baseline(trace_path: str | Path) -> BehavioralBaseline:
    path = Path(trace_path)
    events = read_trace(path)
    event_types = Counter(str(event.get("event_type", "")) for event in events if event.get("event_type"))
    network = sorted(
        {
            str(event.get("target", ""))
            for event in events
            if event.get("event_type") == "network.egress" and event.get("target")
        }
    )
    mcp_targets = sorted(
        {
            str(event.get("target", ""))
            for event in events
            if event.get("event_type") in {"mcp.tool", "mcp.resource", "mcp.prompt"}
            and event.get("target")
        }
    )
    return BehavioralBaseline(
        schema_version=1,
        event_type_counts=dict(sorted(event_types.items())),
        network_destinations=network,
        mcp_targets=mcp_targets,
        source_trace_sha256=sha256_file(path),
    )


def compare_baseline(baseline: BehavioralBaseline, current: BehavioralBaseline) -> DriftResult:
    baseline_network = set(baseline.network_destinations)
    current_network = set(current.network_destinations)
    baseline_mcp = set(baseline.mcp_targets)
    current_mcp = set(current.mcp_targets)
    keys = sorted(set(baseline.event_type_counts) | set(current.event_type_counts))
    deltas = {
        key: current.event_type_counts.get(key, 0) - baseline.event_type_counts.get(key, 0)
        for key in keys
        if current.event_type_counts.get(key, 0) != baseline.event_type_counts.get(key, 0)
    }
    new_network = sorted(current_network - baseline_network)
    missing_network = sorted(baseline_network - current_network)
    new_mcp = sorted(current_mcp - baseline_mcp)
    missing_mcp = sorted(baseline_mcp - current_mcp)
    return DriftResult(
        schema_version=1,
        new_network_destinations=new_network,
        missing_network_destinations=missing_network,
        new_mcp_targets=new_mcp,
        missing_mcp_targets=missing_mcp,
        event_type_count_deltas=deltas,
        drift_detected=bool(new_network or missing_network or new_mcp or missing_mcp or deltas),
        claims_boundary=(
            "This detects drift relative to the supplied trace baseline only. A baseline is not automatically approved behavior, and absent telemetry cannot be interpreted as absence of activity."
        ),
    )


def load_baseline(path: str | Path) -> BehavioralBaseline:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return BehavioralBaseline(
        schema_version=int(payload["schema_version"]),
        event_type_counts={str(k): int(v) for k, v in payload.get("event_type_counts", {}).items()},
        network_destinations=[str(item) for item in payload.get("network_destinations", [])],
        mcp_targets=[str(item) for item in payload.get("mcp_targets", [])],
        source_trace_sha256=str(payload.get("source_trace_sha256", "")),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create or compare OBS-03 behavioral trace baselines")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("trace")
    create.add_argument("--output", required=True)
    compare = sub.add_parser("compare")
    compare.add_argument("baseline")
    compare.add_argument("trace")
    compare.add_argument("--output", default=None)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            baseline = build_baseline(args.trace)
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(baseline.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(json.dumps(baseline.to_dict(), indent=2, sort_keys=True))
            return 0
        baseline = load_baseline(args.baseline)
        current = build_baseline(args.trace)
        result = compare_baseline(baseline, current)
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 1 if result.drift_detected else 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
