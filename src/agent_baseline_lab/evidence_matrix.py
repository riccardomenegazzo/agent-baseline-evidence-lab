from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .evidence import EvidenceStore, sha256_file, verify_bundle
from .trace import read_trace


@dataclass(frozen=True)
class VerificationScenario:
    id: str
    description: str
    internal_verifier_passed: bool | None
    externally_anchored_verifier_passed: bool | None
    alteration_detected_internally: bool | None
    alteration_detected_with_external_anchor: bool | None
    expected_security_property: str
    finding: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _copy_bundle(source: Path, target: Path) -> None:
    shutil.copytree(source, target)


def _regenerate_manifest(root: Path) -> str:
    manifest = EvidenceStore(root).finalize_manifest()
    return sha256_file(manifest)


def _rewrite_anchors_after_trace_truncation(root: Path) -> None:
    trace_path = root / "trace" / "events.ndjson"
    events = read_trace(trace_path)
    if len(events) < 2:
        raise ValueError("coordinated rewrite scenario requires at least two trace events")
    truncated = events[:-1]
    trace_path.write_text(
        "".join(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n" for event in truncated),
        encoding="utf-8",
    )
    assessment_path = root / "assessment.json"
    assessment = json.loads(assessment_path.read_text(encoding="utf-8"))
    metadata = assessment.setdefault("metadata", {})
    metadata["trace_head_sha256"] = truncated[-1]["event_hash"]
    metadata["trace_event_count"] = len(truncated)
    assessment_path.write_text(json.dumps(assessment, indent=2) + "\n", encoding="utf-8")
    _regenerate_manifest(root)


def run_verification_matrix(
    evidence_dir: str | Path,
    *,
    output_path: str | Path | None = None,
) -> tuple[list[VerificationScenario], dict[str, Any]]:
    source = Path(evidence_dir).resolve()
    original_ok, original_errors, original_summary = verify_bundle(source)
    if not original_ok:
        raise ValueError(
            "source evidence bundle must verify before attack simulation: "
            + "; ".join(original_errors)
        )

    original_manifest = str(original_summary.get("manifest_sha256", ""))
    original_trace_head = str(original_summary.get("trace_head_sha256", ""))
    scenarios: list[VerificationScenario] = []

    with tempfile.TemporaryDirectory(prefix="abl-evidence-matrix-") as temp_root:
        temp = Path(temp_root)

        # 1. Alter one evidence file without updating its manifest entry.
        mutation = temp / "single-file-mutation"
        _copy_bundle(source, mutation)
        assessment_path = mutation / "assessment.json"
        assessment_path.write_text(
            assessment_path.read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        internal_ok, _, _ = verify_bundle(mutation)
        external_ok, _, _ = verify_bundle(
            mutation,
            expected_manifest_sha256=original_manifest,
            expected_trace_head=original_trace_head,
        )
        scenarios.append(
            VerificationScenario(
                id="single-file-alteration",
                description="Modify one manifested evidence file without updating the manifest.",
                internal_verifier_passed=internal_ok,
                externally_anchored_verifier_passed=external_ok,
                alteration_detected_internally=not internal_ok,
                alteration_detected_with_external_anchor=not external_ok,
                expected_security_property="integrity",
                finding=(
                    "Detected by the bundle manifest; an external anchor is not required for this "
                    "uncoordinated mutation."
                ),
            )
        )

        # 2. Truncate the trace but leave assessment anchors and manifest untouched.
        truncation = temp / "trace-truncation"
        _copy_bundle(source, truncation)
        trace_path = truncation / "trace" / "events.ndjson"
        events = read_trace(trace_path)
        if len(events) < 2:
            raise ValueError("trace truncation scenario requires at least two events")
        trace_path.write_text(
            "".join(
                json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n"
                for event in events[:-1]
            ),
            encoding="utf-8",
        )
        internal_ok, _, _ = verify_bundle(truncation)
        external_ok, _, _ = verify_bundle(
            truncation,
            expected_manifest_sha256=original_manifest,
            expected_trace_head=original_trace_head,
        )
        scenarios.append(
            VerificationScenario(
                id="trace-truncation",
                description="Remove the final trace event without rewriting assessment anchors or manifest.",
                internal_verifier_passed=internal_ok,
                externally_anchored_verifier_passed=external_ok,
                alteration_detected_internally=not internal_ok,
                alteration_detected_with_external_anchor=not external_ok,
                expected_security_property="integrity-and-exported-trace-completeness",
                finding=(
                    "Detected because the trace count/head no longer matches assessment metadata "
                    "and the manifested file digest changes."
                ),
            )
        )

        # 3. Simulate an attacker able to rewrite the trace, its local anchors, and manifest.
        coordinated = temp / "coordinated-rewrite"
        _copy_bundle(source, coordinated)
        _rewrite_anchors_after_trace_truncation(coordinated)
        internal_ok, _, _ = verify_bundle(coordinated)
        external_ok, _, _ = verify_bundle(
            coordinated,
            expected_manifest_sha256=original_manifest,
            expected_trace_head=original_trace_head,
        )
        scenarios.append(
            VerificationScenario(
                id="coordinated-rewrite",
                description=(
                    "Truncate the trace, rewrite assessment count/head to match it, then regenerate "
                    "the local manifest."
                ),
                internal_verifier_passed=internal_ok,
                externally_anchored_verifier_passed=external_ok,
                alteration_detected_internally=not internal_ok,
                alteration_detected_with_external_anchor=not external_ok,
                expected_security_property="independent-verifiability",
                finding=(
                    "A self-consistent rewritten bundle can pass internal verification. The original "
                    "external manifest/trace anchor detects the rewrite."
                ),
            )
        )

        # 4. No artifact mutation can reveal an event that was never emitted before export.
        scenarios.append(
            VerificationScenario(
                id="event-never-emitted",
                description=(
                    "Assume a material source event happened but was never emitted into the evidence "
                    "pipeline before the bundle was produced."
                ),
                internal_verifier_passed=True,
                externally_anchored_verifier_passed=True,
                alteration_detected_internally=False,
                alteration_detected_with_external_anchor=False,
                expected_security_property="source-completeness",
                finding=(
                    "Neither internal integrity checks nor an external hash anchor can prove the "
                    "existence of an event that never entered the evidence set. Completeness requires "
                    "an independent source-of-record, sequence/checkpoint expectation, or reconciliation "
                    "mechanism in addition to artifact integrity."
                ),
            )
        )

    summary = {
        "schema_version": 1,
        "source_evidence": str(source),
        "source_manifest_sha256": original_manifest,
        "source_trace_head_sha256": original_trace_head,
        "source_trace_event_count": original_summary.get("trace_event_count"),
        "scenario_count": len(scenarios),
        "key_result": (
            "Internal consistency detects uncoordinated alteration and truncation, but a coordinated "
            "rewrite requires an external trust anchor, and source events never emitted cannot be "
            "detected from the exported bundle alone."
        ),
    }
    if output_path is not None:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {"summary": summary, "scenarios": [item.to_dict() for item in scenarios]},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    return scenarios, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run adversarial verification scenarios against an Agent Baseline evidence bundle"
    )
    parser.add_argument("evidence_dir")
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)
    output = args.output or str(Path("reports") / "evidence-verification-matrix.json")
    try:
        scenarios, summary = run_verification_matrix(args.evidence_dir, output_path=output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(summary, indent=2, sort_keys=True))
    for scenario in scenarios:
        print(
            f"{scenario.id}: internal_pass={scenario.internal_verifier_passed} "
            f"external_pass={scenario.externally_anchored_verifier_passed}"
        )
    print(f"Matrix report: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
