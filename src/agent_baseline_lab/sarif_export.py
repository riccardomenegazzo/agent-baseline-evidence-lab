from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _load(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    if not path.is_file():
        raise ValueError(f"input does not exist: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON input {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"input must contain a JSON object: {path}")
    return value


def _level(status: str) -> str | None:
    return {
        "FAIL": "error",
        "ERROR": "error",
        "PARTIAL": "warning",
        "MANUAL": "note",
        "FINDING": "warning",
    }.get(status)


def _evidence_locations(item: dict[str, Any]) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    evidence = item.get("evidence", [])
    if not isinstance(evidence, list):
        return locations
    for entry in evidence:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("path", "")).strip()
        if not path:
            continue
        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                }
            }
        )
    return locations


def build_sarif(
    assessment: dict[str, Any],
    trusted_artifact: dict[str, Any] | None = None,
) -> dict[str, Any]:
    trusted_artifact = trusted_artifact or {}
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    assessment_results = assessment.get("results", [])
    if not isinstance(assessment_results, list):
        raise ValueError("assessment results must be an array")
    for item in assessment_results:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", "ERROR"))
        level = _level(status)
        if level is None:
            continue
        control_id = str(item.get("control_id", "UNKNOWN"))
        rule_id = f"ABL-{control_id}"
        summary = str(item.get("summary", "Agent Baseline evidence finding"))
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": control_id,
                "shortDescription": {"text": f"Agent Baseline control {control_id}"},
                "fullDescription": {
                    "text": "Evidence status exported by Agent Baseline Evidence Lab; not an official conformance result."
                },
                "properties": {"source": "agent-baseline", "controlId": control_id},
            },
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{status}: {summary}"},
            "properties": {
                "status": status,
                "evaluator": str(item.get("evaluator", "")),
                "runId": str(assessment.get("run_id", "")),
            },
        }
        locations = _evidence_locations(item)
        if locations:
            result["locations"] = locations
        results.append(result)

    checks = trusted_artifact.get("checks", []) if trusted_artifact else []
    if isinstance(checks, list):
        for item in checks:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status", ""))
            level = _level(status)
            if level is None:
                continue
            check_id = str(item.get("id", "unknown"))
            rule_id = f"ABL-SUPPLY-{check_id}"
            summary = str(item.get("summary", "Trusted artifact finding"))
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": check_id,
                    "shortDescription": {"text": f"Trusted artifact check: {check_id}"},
                    "fullDescription": {
                        "text": "Software supply-chain evidence exported by Agent Baseline Evidence Lab."
                    },
                    "properties": {"source": "trusted-artifact", "checkId": check_id},
                },
            )
            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"{status}: {summary}"},
                "properties": {
                    "status": status,
                    "artifactStatus": str(trusted_artifact.get("overall_status", "")),
                    "scoutStatus": str(trusted_artifact.get("scout_status", "")),
                },
            }
            dockerfile = str(trusted_artifact.get("dockerfile", "")).strip()
            if dockerfile:
                result["locations"] = [
                    {"physicalLocation": {"artifactLocation": {"uri": dockerfile}}}
                ]
            results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Agent Baseline Evidence Lab",
                        "informationUri": "https://github.com/riccardomenegazzo/agent-baseline-evidence-lab",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
                "properties": {
                    "claimsBoundary": (
                        "SARIF exposes observed blockers and evidence gaps to security tooling; it is not a compliance score or official conformance result."
                    ),
                    "assessmentRunId": str(assessment.get("run_id", "")),
                },
            }
        ],
    }


def export_sarif(
    assessment_path: str | Path,
    *,
    trusted_artifact_path: str | Path | None = None,
    output: str | Path = "reports/agent-governance.sarif",
) -> dict[str, Any]:
    assessment_file = Path(assessment_path)
    trusted_file = Path(trusted_artifact_path) if trusted_artifact_path else None
    payload = build_sarif(
        _load(assessment_file),
        _load(trusted_file) if trusted_file else None,
    )
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export Agent Baseline and trusted-artifact findings as SARIF 2.1.0")
    parser.add_argument("assessment")
    parser.add_argument("--trusted-artifact", default=None)
    parser.add_argument("--output", default="reports/agent-governance.sarif")
    args = parser.parse_args(argv)
    try:
        payload = export_sarif(
            args.assessment,
            trusted_artifact_path=args.trusted_artifact,
            output=args.output,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    result_count = len(payload["runs"][0]["results"])
    print(f"SARIF written: {args.output} ({result_count} finding(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
