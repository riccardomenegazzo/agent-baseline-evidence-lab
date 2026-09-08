from __future__ import annotations

import argparse
import hashlib
import html
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .evidence import sha256_file, verify_bundle

EXPERIMENT_TYPE = "urn:agent-baseline-evidence-lab:controlled-experiment:v1"


@dataclass(frozen=True)
class ExperimentDimension:
    name: str
    role: str
    required: bool
    before: str | None
    after: str | None
    status: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ControlledExperimentStatement:
    schema_version: int
    statement_type: str
    generated_at: str
    before_run_id: str
    after_run_id: str
    invariant_checks: list[ExperimentDimension]
    treatment_checks: list[ExperimentDimension]
    eligibility: str
    eligible_for_causal_interpretation: bool
    treatment_changed: bool
    missing_required_invariants: list[str]
    differing_required_invariants: list[str]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "statement_type": self.statement_type,
            "generated_at": self.generated_at,
            "before_run_id": self.before_run_id,
            "after_run_id": self.after_run_id,
            "invariant_checks": [item.to_dict() for item in self.invariant_checks],
            "treatment_checks": [item.to_dict() for item in self.treatment_checks],
            "eligibility": self.eligibility,
            "eligible_for_causal_interpretation": self.eligible_for_causal_interpretation,
            "treatment_changed": self.treatment_changed,
            "missing_required_invariants": self.missing_required_invariants,
            "differing_required_invariants": self.differing_required_invariants,
            "claims_boundary": self.claims_boundary,
        }


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _get(payload: dict[str, Any], *parts: str) -> Any:
    current: Any = payload
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _canonical_sha256(payload: Any) -> str:
    raw = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sorted_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(str(item) for item in value)


def _run_context(root: Path) -> dict[str, Any]:
    ok, errors, bundle_summary = verify_bundle(root)
    if not ok:
        raise ValueError(
            f"evidence bundle {root} must verify before experiment comparison: "
            + "; ".join(errors)
        )

    assessment = _load_json(root / "assessment.json")
    if not assessment:
        raise ValueError(f"assessment.json is missing or malformed in {root}")
    config = _load_yaml(root / "inputs" / "assessment-config.yaml")
    agent_run = _load_json(root / "observations" / "agent-run.json")
    session = agent_run.get("session", {}) if isinstance(agent_run, dict) else {}
    if not isinstance(session, dict):
        session = {}

    runtime_evidence = root / "controls" / "CON-03" / "sbx-version.txt"
    runtime_sha = sha256_file(runtime_evidence) if runtime_evidence.is_file() else None

    treatment = {
        "network": {
            "required_allows": _sorted_strings(
                _get(config, "sandbox", "network", "required_allows")
            ),
            "required_denies": _sorted_strings(
                _get(config, "sandbox", "network", "required_denies")
            ),
        },
        "mcp_static_servers": _sorted_strings(
            _get(config, "sandbox", "mcp", "static_servers")
        ),
        "capability_profile": _get(config, "sandbox", "capability_profile") or {},
        "mcp_policy_files": _sorted_strings(
            _get(config, "assessment", "mcp_policy_files")
        ),
        "declared_access": _get(config, "agent", "access") or {},
        "declared_capabilities": _get(config, "agent", "capabilities") or [],
    }

    metadata = assessment.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    return {
        "run_id": str(assessment.get("run_id") or root.name),
        "baseline_version": str(assessment.get("baseline_version", "")) or None,
        "agent_id": str(metadata.get("agent_id", "")) or None,
        "task_id": str(session.get("task_id") or _get(config, "assessment", "task_id") or "") or None,
        "task_sha256": str(_get(session, "task", "sha256") or "") or None,
        "workspace_before_sha256": str(
            _get(session, "workspace_before", "root_sha256") or ""
        ) or None,
        "agent_runtime": str(session.get("agent") or _get(config, "sandbox", "agent") or "") or None,
        "runtime_fingerprint": runtime_sha,
        "treatment_fingerprint": _canonical_sha256(treatment),
        "treatment": treatment,
        "manifest_sha256": str(bundle_summary.get("manifest_sha256", "")),
    }


def _dimension(
    name: str,
    role: str,
    required: bool,
    before: str | None,
    after: str | None,
    evidence: str,
) -> ExperimentDimension:
    if before is None or after is None:
        status = "MISSING"
    elif before == after:
        status = "MATCH"
    else:
        status = "DIFFERENT"
    return ExperimentDimension(
        name=name,
        role=role,
        required=required,
        before=before,
        after=after,
        status=status,
        evidence=evidence,
    )


def build_experiment_statement(
    before_dir: str | Path,
    after_dir: str | Path,
) -> ControlledExperimentStatement:
    before_root = Path(before_dir).resolve()
    after_root = Path(after_dir).resolve()
    before = _run_context(before_root)
    after = _run_context(after_root)

    if before["run_id"] == after["run_id"]:
        raise ValueError("controlled experiment requires distinct before and after run_id values")

    invariant_specs = [
        ("baseline_version", True, "assessment.json:baseline_version"),
        ("agent_id", True, "assessment.json:metadata.agent_id"),
        ("task_id", True, "observations/agent-run.json:session.task_id"),
        ("task_sha256", True, "observations/agent-run.json:session.task.sha256"),
        (
            "workspace_before_sha256",
            True,
            "observations/agent-run.json:session.workspace_before.root_sha256",
        ),
        ("agent_runtime", True, "observations/agent-run.json:session.agent"),
        (
            "runtime_fingerprint",
            True,
            "controls/CON-03/sbx-version.txt:sha256",
        ),
    ]
    invariant_checks = [
        _dimension(
            name,
            "invariant",
            required,
            before.get(name),
            after.get(name),
            evidence,
        )
        for name, required, evidence in invariant_specs
    ]

    treatment_checks = [
        _dimension(
            "governance_treatment_fingerprint",
            "treatment",
            True,
            str(before["treatment_fingerprint"]),
            str(after["treatment_fingerprint"]),
            "inputs/assessment-config.yaml:governance-projection",
        )
    ]

    missing = [
        item.name
        for item in invariant_checks
        if item.required and item.status == "MISSING"
    ]
    differing = [
        item.name
        for item in invariant_checks
        if item.required and item.status == "DIFFERENT"
    ]
    treatment_changed = any(item.status == "DIFFERENT" for item in treatment_checks)

    if missing:
        eligibility = "INSUFFICIENT_EVIDENCE"
        eligible = False
    elif differing or not treatment_changed:
        eligibility = "NOT_ELIGIBLE"
        eligible = False
    else:
        eligibility = "ELIGIBLE"
        eligible = True

    return ControlledExperimentStatement(
        schema_version=1,
        statement_type=EXPERIMENT_TYPE,
        generated_at=_utc_now(),
        before_run_id=str(before["run_id"]),
        after_run_id=str(after["run_id"]),
        invariant_checks=invariant_checks,
        treatment_checks=treatment_checks,
        eligibility=eligibility,
        eligible_for_causal_interpretation=eligible,
        treatment_changed=treatment_changed,
        missing_required_invariants=missing,
        differing_required_invariants=differing,
        claims_boundary=(
            "ELIGIBLE means the required measured invariants match and the declared governance "
            "treatment differs. It does not prove causality, rule out unmeasured confounders, or "
            "establish that every environmental variable was held constant. INSUFFICIENT_EVIDENCE "
            "is intentionally fail-closed when a required invariant cannot be measured."
        ),
    )


def _projection(payload: ControlledExperimentStatement | dict[str, Any]) -> dict[str, Any]:
    value = payload.to_dict() if isinstance(payload, ControlledExperimentStatement) else payload
    return {
        "schema_version": value.get("schema_version"),
        "statement_type": value.get("statement_type"),
        "before_run_id": value.get("before_run_id"),
        "after_run_id": value.get("after_run_id"),
        "invariant_checks": value.get("invariant_checks"),
        "treatment_checks": value.get("treatment_checks"),
        "eligibility": value.get("eligibility"),
        "eligible_for_causal_interpretation": value.get(
            "eligible_for_causal_interpretation"
        ),
        "treatment_changed": value.get("treatment_changed"),
        "missing_required_invariants": value.get("missing_required_invariants"),
        "differing_required_invariants": value.get("differing_required_invariants"),
        "claims_boundary": value.get("claims_boundary"),
    }


def write_statement_json(
    statement: ControlledExperimentStatement,
    output_path: str | Path,
) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(statement.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output


def write_statement_html(
    statement: ControlledExperimentStatement,
    output_path: str | Path,
) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    def rows(items: list[ExperimentDimension]) -> str:
        return "\n".join(
            "<tr>"
            f"<td>{html.escape(item.name)}</td>"
            f"<td>{html.escape(str(item.before))}</td>"
            f"<td>{html.escape(str(item.after))}</td>"
            f"<td>{html.escape(item.status)}</td>"
            "</tr>"
            for item in items
        )

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Controlled Experiment {html.escape(statement.before_run_id)} → {html.escape(statement.after_run_id)}</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 1100px; margin: 40px auto; padding: 0 20px; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 24px; }}
th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left; word-break: break-word; }}
code {{ word-break: break-all; }}
</style>
</head>
<body>
<h1>Controlled Experiment Protocol</h1>
<p><strong>Before:</strong> {html.escape(statement.before_run_id)}<br>
<strong>After:</strong> {html.escape(statement.after_run_id)}<br>
<strong>Eligibility:</strong> {html.escape(statement.eligibility)}<br>
<strong>Treatment changed:</strong> {statement.treatment_changed}</p>
<h2>Required invariants</h2>
<table><thead><tr><th>Dimension</th><th>Before</th><th>After</th><th>Status</th></tr></thead>
<tbody>{rows(statement.invariant_checks)}</tbody></table>
<h2>Treatment</h2>
<table><thead><tr><th>Dimension</th><th>Before</th><th>After</th><th>Status</th></tr></thead>
<tbody>{rows(statement.treatment_checks)}</tbody></table>
<h2>Claims boundary</h2><p>{html.escape(statement.claims_boundary)}</p>
</body></html>
"""
    output.write_text(document, encoding="utf-8")
    return output


def verify_statement(
    statement_path: str | Path,
    before_dir: str | Path,
    after_dir: str | Path,
) -> tuple[bool, list[str], dict[str, Any]]:
    path = Path(statement_path)
    errors: list[str] = []
    try:
        recorded = json.loads(path.read_text(encoding="utf-8"))
        expected = build_experiment_statement(before_dir, after_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return False, [f"controlled experiment statement cannot be verified: {exc}"], {}

    if _projection(recorded) != _projection(expected):
        errors.append("recorded experiment statement does not match recomputed evidence")

    return not errors, errors, {
        "before_run_id": expected.before_run_id,
        "after_run_id": expected.after_run_id,
        "eligibility": expected.eligibility,
        "eligible_for_causal_interpretation": expected.eligible_for_causal_interpretation,
        "treatment_changed": expected.treatment_changed,
        "statement_sha256": sha256_file(path),
        "valid": not errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create or verify a controlled before/after experiment statement"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create")
    create.add_argument("before")
    create.add_argument("after")
    create.add_argument("--output", required=True)
    create.add_argument("--html", default=None)

    verify = sub.add_parser("verify")
    verify.add_argument("statement")
    verify.add_argument("before")
    verify.add_argument("after")

    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            statement = build_experiment_statement(args.before, args.after)
            output = write_statement_json(statement, args.output)
            if args.html:
                write_statement_html(statement, args.html)
            print(json.dumps(statement.to_dict(), indent=2, sort_keys=True))
            print(f"Experiment JSON: {output}")
            if args.html:
                print(f"Experiment HTML: {args.html}")
            return 0

        ok, errors, summary = verify_statement(
            args.statement,
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
