from __future__ import annotations

import argparse
import html
import json
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .evidence import sha256_file, verify_bundle

DELTA_TYPE = "urn:agent-baseline-evidence-lab:governance-delta:v1"


@dataclass(frozen=True)
class RunAnchor:
    run_id: str
    baseline_version: str
    manifest_sha256: str
    trace_head_sha256: str
    trace_event_count: int
    assessment_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ControlDelta:
    control_id: str
    before_status: str
    after_status: str
    change_type: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class GovernanceDelta:
    schema_version: int
    statement_type: str
    generated_at: str
    before: RunAnchor
    after: RunAnchor
    comparable: bool
    comparison_warnings: list[str]
    changes: list[ControlDelta]
    change_counts: dict[str, int]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "statement_type": self.statement_type,
            "generated_at": self.generated_at,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "comparable": self.comparable,
            "comparison_warnings": self.comparison_warnings,
            "changes": [item.to_dict() for item in self.changes],
            "change_counts": self.change_counts,
            "claims_boundary": self.claims_boundary,
        }


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _assessment(root: Path) -> dict[str, Any]:
    path = root / "assessment.json"
    if not path.is_file():
        raise ValueError(f"assessment.json is missing from {root}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"assessment.json is not an object: {root}")
    return payload


def _result_map(assessment: dict[str, Any]) -> dict[str, str]:
    results = assessment.get("results", [])
    if not isinstance(results, list):
        raise ValueError("assessment results must be a list")
    mapped: dict[str, str] = {}
    for index, item in enumerate(results, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"assessment result {index} is malformed")
        control_id = str(item.get("control_id", "")).strip()
        status = str(item.get("status", "")).strip()
        if not control_id or not status:
            raise ValueError(f"assessment result {index} is missing control_id/status")
        if control_id in mapped:
            raise ValueError(f"duplicate control result: {control_id}")
        mapped[control_id] = status
    if not mapped:
        raise ValueError("assessment contains no control results")
    return mapped


def _anchor(root: Path, assessment: dict[str, Any]) -> RunAnchor:
    ok, errors, summary = verify_bundle(root)
    if not ok:
        raise ValueError(
            f"evidence bundle {root} must verify before comparison: " + "; ".join(errors)
        )
    assessment_path = root / "assessment.json"
    return RunAnchor(
        run_id=str(assessment.get("run_id") or root.name),
        baseline_version=str(assessment.get("baseline_version", "")),
        manifest_sha256=str(summary.get("manifest_sha256", "")),
        trace_head_sha256=str(summary.get("trace_head_sha256", "")),
        trace_event_count=int(summary.get("trace_event_count", 0)),
        assessment_sha256=sha256_file(assessment_path),
    )


def classify_change(before: str, after: str) -> str:
    if before == after:
        return "unchanged"
    if before == "N/A" or after == "N/A":
        return "scope-change"
    if before == "ERROR" and after != "ERROR":
        return "evaluator-recovery"
    if before != "ERROR" and after == "ERROR":
        return "evaluator-error"
    if before == "MANUAL" and after != "MANUAL":
        return "evidence-gain"
    if before != "MANUAL" and after == "MANUAL":
        return "evidence-loss"
    if (before, after) in {
        ("FAIL", "PARTIAL"),
        ("FAIL", "PASS"),
        ("PARTIAL", "PASS"),
    }:
        return "control-improvement"
    if (before, after) in {
        ("PASS", "PARTIAL"),
        ("PASS", "FAIL"),
        ("PARTIAL", "FAIL"),
    }:
        return "control-regression"
    return "other-change"


def build_delta(before_dir: str | Path, after_dir: str | Path) -> GovernanceDelta:
    before_root = Path(before_dir).resolve()
    after_root = Path(after_dir).resolve()
    before_assessment = _assessment(before_root)
    after_assessment = _assessment(after_root)
    before_anchor = _anchor(before_root, before_assessment)
    after_anchor = _anchor(after_root, after_assessment)

    if before_anchor.run_id == after_anchor.run_id and before_root != after_root:
        raise ValueError("before and after bundles reuse the same run_id")
    if before_anchor.baseline_version != after_anchor.baseline_version:
        raise ValueError(
            "baseline version mismatch; governance delta requires the same baseline version"
        )

    before_results = _result_map(before_assessment)
    after_results = _result_map(after_assessment)
    if set(before_results) != set(after_results):
        missing_after = sorted(set(before_results) - set(after_results))
        missing_before = sorted(set(after_results) - set(before_results))
        raise ValueError(
            "control set mismatch; missing_after="
            f"{missing_after}, missing_before={missing_before}"
        )

    warnings: list[str] = []
    before_agent = str(before_assessment.get("metadata", {}).get("agent_id", ""))
    after_agent = str(after_assessment.get("metadata", {}).get("agent_id", ""))
    if before_agent and after_agent and before_agent != after_agent:
        warnings.append(
            "agent_id differs between runs; treat the delta as cross-agent evidence, not a controlled before/after experiment"
        )

    changes = [
        ControlDelta(
            control_id=control_id,
            before_status=before_results[control_id],
            after_status=after_results[control_id],
            change_type=classify_change(
                before_results[control_id],
                after_results[control_id],
            ),
        )
        for control_id in sorted(before_results)
    ]
    counts = Counter(item.change_type for item in changes)
    return GovernanceDelta(
        schema_version=1,
        statement_type=DELTA_TYPE,
        generated_at=_utc_now(),
        before=before_anchor,
        after=after_anchor,
        comparable=True,
        comparison_warnings=warnings,
        changes=changes,
        change_counts=dict(sorted(counts.items())),
        claims_boundary=(
            "This delta compares two independently verified implementation-evidence bundles. "
            "It does not compute a security score and does not prove that a governance change caused "
            "the observed status transitions. 'Evidence gain' means a previously manual control became "
            "evaluated; the resulting status may still be FAIL. Causal claims require a controlled experiment."
        ),
    )


def _verification_projection(delta: GovernanceDelta | dict[str, Any]) -> dict[str, Any]:
    payload = delta.to_dict() if isinstance(delta, GovernanceDelta) else delta
    return {
        "schema_version": payload.get("schema_version"),
        "statement_type": payload.get("statement_type"),
        "before": payload.get("before"),
        "after": payload.get("after"),
        "comparable": payload.get("comparable"),
        "comparison_warnings": payload.get("comparison_warnings"),
        "changes": payload.get("changes"),
        "change_counts": payload.get("change_counts"),
        "claims_boundary": payload.get("claims_boundary"),
    }


def verify_delta(
    delta_path: str | Path,
    before_dir: str | Path,
    after_dir: str | Path,
) -> tuple[bool, list[str], dict[str, Any]]:
    path = Path(delta_path)
    errors: list[str] = []
    try:
        recorded = json.loads(path.read_text(encoding="utf-8"))
        expected = build_delta(before_dir, after_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return False, [f"governance delta cannot be verified: {exc}"], {}

    if _verification_projection(recorded) != _verification_projection(expected):
        errors.append("recorded governance delta does not match recomputed verified bundles")

    summary = {
        "before_run_id": expected.before.run_id,
        "after_run_id": expected.after.run_id,
        "before_manifest_sha256": expected.before.manifest_sha256,
        "after_manifest_sha256": expected.after.manifest_sha256,
        "change_counts": expected.change_counts,
        "delta_sha256": sha256_file(path),
        "valid": not errors,
    }
    return not errors, errors, summary


def write_delta_json(delta: GovernanceDelta, path: str | Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(delta.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output


def write_delta_html(delta: GovernanceDelta, path: str | Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(item.control_id)}</td>"
        f"<td>{html.escape(item.before_status)}</td>"
        f"<td>{html.escape(item.after_status)}</td>"
        f"<td>{html.escape(item.change_type)}</td>"
        "</tr>"
        for item in delta.changes
        if item.change_type != "unchanged"
    )
    if not rows:
        rows = '<tr><td colspan="4">No control-status changes observed.</td></tr>'
    counts = " ".join(
        f"{html.escape(name)}={count}"
        for name, count in sorted(delta.change_counts.items())
    )
    warning_html = "".join(
        f"<li>{html.escape(item)}</li>" for item in delta.comparison_warnings
    ) or "<li>None</li>"
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Governance Delta {html.escape(delta.before.run_id)} → {html.escape(delta.after.run_id)}</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 1100px; margin: 40px auto; padding: 0 20px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left; }}
code {{ word-break: break-all; }}
.small {{ opacity: .78; }}
</style>
</head>
<body>
<h1>Governance Delta</h1>
<p><strong>Before:</strong> {html.escape(delta.before.run_id)}<br>
<strong>After:</strong> {html.escape(delta.after.run_id)}<br>
<strong>Baseline:</strong> {html.escape(delta.before.baseline_version)}</p>
<p><strong>Change counts:</strong> {html.escape(counts)}</p>
<h2>Comparison warnings</h2><ul>{warning_html}</ul>
<h2>Changed controls</h2>
<table><thead><tr><th>Control</th><th>Before</th><th>After</th><th>Classification</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>Evidence anchors</h2>
<p class="small">Before manifest: <code>{html.escape(delta.before.manifest_sha256)}</code><br>
After manifest: <code>{html.escape(delta.after.manifest_sha256)}</code><br>
Before trace head: <code>{html.escape(delta.before.trace_head_sha256)}</code><br>
After trace head: <code>{html.escape(delta.after.trace_head_sha256)}</code></p>
<h2>Claims boundary</h2><p>{html.escape(delta.claims_boundary)}</p>
</body></html>
"""
    output.write_text(document, encoding="utf-8")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create or verify a before/after governance evidence delta"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create")
    create.add_argument("before")
    create.add_argument("after")
    create.add_argument("--output", required=True)
    create.add_argument("--html", default=None)

    verify = sub.add_parser("verify")
    verify.add_argument("delta")
    verify.add_argument("before")
    verify.add_argument("after")

    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            delta = build_delta(args.before, args.after)
            output = write_delta_json(delta, args.output)
            if args.html:
                write_delta_html(delta, args.html)
            print(json.dumps(delta.to_dict(), indent=2, sort_keys=True))
            print(f"Delta JSON: {output}")
            if args.html:
                print(f"Delta HTML: {args.html}")
            return 0

        ok, errors, summary = verify_delta(
            args.delta,
            args.before,
            args.after,
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        for error in errors:
            print(f"ERROR: {error}")
        return 0 if ok else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
