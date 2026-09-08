from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .drift import build_baseline, compare_baseline, load_baseline
from .evidence import verify_bundle
from .evidence_matrix import run_verification_matrix
from .incident_bundle import verify_incident_bundle
from .quarantine import verify_registry
from .signing import verify_signature
from .unintended_action import analyze_changed_paths


@dataclass(frozen=True)
class AssuranceCheck:
    name: str
    status: str
    blocking: bool
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AssuranceSummary:
    schema_version: int
    generated_at: str
    assessment_run_id: str
    checks: list[AssuranceCheck]
    blocking_failures: int
    findings: int
    overall_status: str
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "assessment_run_id": self.assessment_run_id,
            "checks": [check.to_dict() for check in self.checks],
            "blocking_failures": self.blocking_failures,
            "findings": self.findings,
            "overall_status": self.overall_status,
            "claims_boundary": self.claims_boundary,
        }


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _latest(paths: list[Path]) -> Path | None:
    existing = [path for path in paths if path.exists()]
    return max(existing, key=lambda path: path.stat().st_mtime) if existing else None


def _latest_dir(root: Path, pattern: str) -> Path | None:
    return _latest([path for path in root.glob(pattern) if path.is_dir()])


def _latest_file(root: Path, pattern: str) -> Path | None:
    return _latest([path for path in root.glob(pattern) if path.is_file()])


def run_assurance_suite(root_path: str | Path = ".") -> AssuranceSummary:
    root = Path(root_path).resolve()
    evidence_dir = _latest_dir(root / "evidence", "abl-*")
    if evidence_dir is None:
        raise ValueError("no assessment evidence bundle found")
    run_id = evidence_dir.name
    checks: list[AssuranceCheck] = []

    bundle_ok, bundle_errors, bundle_summary = verify_bundle(evidence_dir)
    checks.append(
        AssuranceCheck(
            name="assessment-bundle-integrity",
            status="PASS" if bundle_ok else "FAIL",
            blocking=True,
            details={"errors": bundle_errors, **bundle_summary},
        )
    )

    matrix_output = root / "reports" / f"{run_id}.evidence-matrix.json"
    scenarios, matrix_summary = run_verification_matrix(
        evidence_dir,
        output_path=matrix_output,
    )
    scenario_map = {scenario.id: scenario for scenario in scenarios}
    expected_matrix = (
        scenario_map["single-file-alteration"].internal_verifier_passed is False
        and scenario_map["trace-truncation"].internal_verifier_passed is False
        and scenario_map["coordinated-rewrite"].internal_verifier_passed is True
        and scenario_map["coordinated-rewrite"].externally_anchored_verifier_passed is False
        and scenario_map["event-never-emitted"].internal_verifier_passed is True
    )
    checks.append(
        AssuranceCheck(
            name="evidence-trust-boundary-regression",
            status="PASS" if expected_matrix else "FAIL",
            blocking=True,
            details={
                "report": str(matrix_output),
                "key_result": matrix_summary.get("key_result"),
            },
        )
    )

    agent_run = _latest_dir(root / "agent-runs", "agent-*")
    if agent_run is not None:
        changes_path = agent_run / "workspace-changes.json"
        if changes_path.exists():
            changes = json.loads(changes_path.read_text(encoding="utf-8"))
            unintended = analyze_changed_paths(changes)
            checks.append(
                AssuranceCheck(
                    name="credential-sensitive-co-change",
                    status="FINDING" if unintended.co_change_detected else "PASS",
                    blocking=False,
                    details=unintended.to_dict(),
                )
            )

    baseline_path = root / ".abl" / "baselines" / "behavior.json"
    trace_path = evidence_dir / "trace" / "events.ndjson"
    if baseline_path.exists() and trace_path.exists():
        drift = compare_baseline(load_baseline(baseline_path), build_baseline(trace_path))
        checks.append(
            AssuranceCheck(
                name="behavioral-drift",
                status="FINDING" if drift.drift_detected else "PASS",
                blocking=False,
                details=drift.to_dict(),
            )
        )
    else:
        checks.append(
            AssuranceCheck(
                name="behavioral-drift",
                status="NOT_RUN",
                blocking=False,
                details={"reason": "no retained behavioral baseline"},
            )
        )

    attestation = root / "reports" / f"{run_id}.attestation.json"
    signature = root / "reports" / f"{run_id}.attestation.json.ed25519.json"
    public_key = root / ".abl" / "keys" / "attestation-public.json"
    if signature.exists() and attestation.exists():
        signature_ok, signature_errors, signature_summary = verify_signature(
            attestation,
            signature,
            public_key_path=public_key if public_key.exists() else None,
        )
        checks.append(
            AssuranceCheck(
                name="attestation-signature",
                status="PASS" if signature_ok else "FAIL",
                blocking=True,
                details={"errors": signature_errors, **signature_summary},
            )
        )
    else:
        checks.append(
            AssuranceCheck(
                name="attestation-signature",
                status="NOT_RUN",
                blocking=False,
                details={"reason": "no signature envelope for latest attestation"},
            )
        )

    incident = root / "reports" / f"{run_id}.incident.json"
    if incident.exists():
        incident_ok, incident_errors, incident_summary = verify_incident_bundle(incident)
        checks.append(
            AssuranceCheck(
                name="incident-bundle",
                status="PASS" if incident_ok else "FAIL",
                blocking=True,
                details={"errors": incident_errors, **incident_summary},
            )
        )

    registry = root / ".abl" / "quarantine" / "registry.ndjson"
    if registry.exists():
        registry_ok, registry_errors, registry_summary = verify_registry(registry)
        checks.append(
            AssuranceCheck(
                name="quarantine-registry",
                status="PASS" if registry_ok else "FAIL",
                blocking=True,
                details={"errors": registry_errors, **registry_summary},
            )
        )

    blocking_failures = sum(check.blocking and check.status == "FAIL" for check in checks)
    findings = sum(check.status == "FINDING" for check in checks)
    overall = "FAIL" if blocking_failures else "PASS_WITH_FINDINGS" if findings else "PASS"
    return AssuranceSummary(
        schema_version=1,
        generated_at=_utc_now(),
        assessment_run_id=run_id,
        checks=checks,
        blocking_failures=blocking_failures,
        findings=findings,
        overall_status=overall,
        claims_boundary=(
            "This suite verifies the latest locally available evidence and highlights non-blocking risk signals. "
            "PASS does not imply Agent Baseline conformance, source completeness, external key identity, or live Docker AI Governance coverage that was not collected."
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the read-only post-run assurance suite")
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default="reports/assurance-summary.json")
    args = parser.parse_args(argv)
    try:
        summary = run_assurance_suite(args.root)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    return 1 if summary.blocking_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
