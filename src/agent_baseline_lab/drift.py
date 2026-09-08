from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .trace import read_trace


@dataclass(frozen=True)
class BehaviorProfile:
    schema_version: int
    artifact_type: str
    profile_id: str
    created_at: str
    trace_sha256: str
    event_count: int
    destinations: list[str]
    mcp_tools: list[str]
    event_type_counts: dict[str, int]
    numeric_totals: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DriftResult:
    schema_version: int
    artifact_type: str
    baseline_profile_id: str
    compared_at: str
    new_destinations: list[str]
    missing_destinations: list[str]
    new_mcp_tools: list[str]
    missing_mcp_tools: list[str]
    event_type_delta: dict[str, int]
    numeric_total_delta: dict[str, float]
    drift_detected: bool
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _numeric_totals(events: list[dict[str, Any]]) -> dict[str, float]:
    totals: dict[str, float] = {}
    interesting = {"cost", "tokens", "bytes", "duration_ms", "cpu_ms", "memory_bytes"}
    for event in events:
        attributes = event.get("attributes", {})
        if not isinstance(attributes, dict):
            continue
        for key, value in attributes.items():
            lowered = str(key).lower()
            if lowered not in interesting or isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                totals[lowered] = totals.get(lowered, 0.0) + float(value)
    return dict(sorted(totals.items()))


def build_profile(trace_path: str | Path, *, profile_id: str | None = None) -> BehaviorProfile:
    path = Path(trace_path)
    events = read_trace(path)
    destinations: set[str] = set()
    tools: set[str] = set()
    counts = Counter(str(event.get("event_type", "")) for event in events)
    for event in events:
        event_type = str(event.get("event_type", ""))
        target = str(event.get("target", "") or "")
        attributes = event.get("attributes", {}) if isinstance(event.get("attributes"), dict) else {}
        if event_type == "network.egress":
            resource = str(attributes.get("resource_id", "") or target)
            if resource:
                destinations.add(resource)
        if event_type == "mcp.tool":
            resource = str(attributes.get("resource_id", "") or target or event.get("action", ""))
            if resource:
                tools.add(resource)
    digest = _sha256_file(path)
    return BehaviorProfile(
        schema_version=1,
        artifact_type="behavior-drift-profile",
        profile_id=profile_id or f"profile-{digest[:16]}",
        created_at=_utc_now(),
        trace_sha256=digest,
        event_count=len(events),
        destinations=sorted(destinations),
        mcp_tools=sorted(tools),
        event_type_counts=dict(sorted(counts.items())),
        numeric_totals=_numeric_totals(events),
    )


def compare_profile(profile: BehaviorProfile, trace_path: str | Path) -> DriftResult:
    current = build_profile(trace_path, profile_id="current")
    baseline_destinations = set(profile.destinations)
    current_destinations = set(current.destinations)
    baseline_tools = set(profile.mcp_tools)
    current_tools = set(current.mcp_tools)
    all_types = set(profile.event_type_counts) | set(current.event_type_counts)
    event_delta = {
        key: current.event_type_counts.get(key, 0) - profile.event_type_counts.get(key, 0)
        for key in sorted(all_types)
        if current.event_type_counts.get(key, 0) != profile.event_type_counts.get(key, 0)
    }
    all_numeric = set(profile.numeric_totals) | set(current.numeric_totals)
    numeric_delta = {
        key: current.numeric_totals.get(key, 0.0) - profile.numeric_totals.get(key, 0.0)
        for key in sorted(all_numeric)
        if current.numeric_totals.get(key, 0.0) != profile.numeric_totals.get(key, 0.0)
    }
    new_destinations = sorted(current_destinations - baseline_destinations)
    missing_destinations = sorted(baseline_destinations - current_destinations)
    new_tools = sorted(current_tools - baseline_tools)
    missing_tools = sorted(baseline_tools - current_tools)
    drift = bool(new_destinations or missing_destinations or new_tools or missing_tools or event_delta or numeric_delta)
    return DriftResult(
        schema_version=1,
        artifact_type="behavior-drift-report",
        baseline_profile_id=profile.profile_id,
        compared_at=_utc_now(),
        new_destinations=new_destinations,
        missing_destinations=missing_destinations,
        new_mcp_tools=new_tools,
        missing_mcp_tools=missing_tools,
        event_type_delta=event_delta,
        numeric_total_delta=numeric_delta,
        drift_detected=drift,
        claims_boundary=(
            "Drift indicates difference from the selected baseline, not maliciousness. Destination/tool "
            "sets are derived only from events present in the normalized trace, so source telemetry "
            "completeness remains a separate evidence requirement."
        ),
    )


def load_profile(path: str | Path) -> BehaviorProfile:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return BehaviorProfile(**payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and compare OBS-03 behavior drift profiles")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("trace")
    create.add_argument("--profile-id", default=None)
    create.add_argument("--output", required=True)
    compare = sub.add_parser("compare")
    compare.add_argument("profile")
    compare.add_argument("trace")
    compare.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            result: BehaviorProfile | DriftResult = build_profile(args.trace, profile_id=args.profile_id)
        else:
            result = compare_profile(load_profile(args.profile), args.trace)
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
