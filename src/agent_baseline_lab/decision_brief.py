from __future__ import annotations

import argparse
import html
import json
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import Status


@dataclass(frozen=True)
class DecisionBrief:
    schema_version: int
    generated_at: str
    decision: str
    assessment_run_id: str
    baseline_version: str
    assessment_counts: dict[str, int]
    trusted_artifact_status: str
    scout_status: str
    assurance_status: str
    blockers: list[str]
    evidence_gaps: list[str]
    observed_strengths: list[str]
    recommended_next_actions: list[str]
    source_artifacts: dict[str, str]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _load_json(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    if not path.is_file():
        raise ValueError(f"JSON input does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON input {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"JSON input must be an object: {path}")
    return payload


def _assessment_summary(payload: dict[str, Any]) -> tuple[Counter[str], list[str], list[str], list[str]]:
    counts: Counter[str] = Counter()
    blockers: list[str] = []
    gaps: list[str] = []
    strengths: list[str] = []
    results = payload.get("results", [])
    if not isinstance(results, list):
        raise ValueError("assessment results must be an array")
    seen: set[str] = set()
    for index, item in enumerate(results, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"assessment result {index} must be an object")
        status = item.get("status")
        if not isinstance(status, str) or status not in {value.value for value in Status}:
            raise ValueError(f"assessment result {index} has an unsupported status")
        control_id = item.get("control_id")
        if not isinstance(control_id, str) or not control_id.strip():
            raise ValueError(f"assessment result {index} has no control_id")
        if control_id in seen:
            raise ValueError(f"duplicate assessment control_id: {control_id}")
        seen.add(control_id)
        summary = str(item.get("summary", "")).strip()
        counts[status] += 1
        label = f"{control_id}: {summary}" if summary else control_id
        if status in {"FAIL", "ERROR"}:
            blockers.append(label)
        elif status in {"PARTIAL", "MANUAL"}:
            gaps.append(label)
        elif status == "PASS":
            strengths.append(label)
    if not results:
        gaps.append("Assessment contains no control results; governance evidence is missing.")
    elif counts["N/A"] == len(results):
        gaps.append("All supplied controls are N/A; no applicable governance evidence was assessed.")
    return counts, blockers, gaps, strengths


def build_decision_brief(
    assessment: dict[str, Any],
    *,
    trusted_artifact: dict[str, Any] | None = None,
    assurance: dict[str, Any] | None = None,
    require_trusted_artifact: bool = False,
    require_scout: bool = False,
) -> DecisionBrief:
    trusted_artifact = trusted_artifact or {}
    assurance = assurance or {}
    counts, blockers, gaps, strengths = _assessment_summary(assessment)

    artifact_status = str(trusted_artifact.get("overall_status", "NOT_RUN")) if trusted_artifact else "NOT_RUN"
    scout_status = str(trusted_artifact.get("scout_status", "NOT_RUN")) if trusted_artifact else "NOT_RUN"
    assurance_status = str(assurance.get("overall_status", "NOT_RUN")) if assurance else "NOT_RUN"

    if trusted_artifact:
        checks = trusted_artifact.get("checks", [])
        if not isinstance(checks, list):
            raise ValueError("trusted-artifact checks must be an array")
        if not checks:
            gaps.append("Trusted artifact report contains no verification checks.")
        for item in checks:
            if not isinstance(item, dict):
                raise ValueError("trusted-artifact check must be an object")
            status = item.get("status")
            if not isinstance(status, str) or status not in {"PASS", "FAIL", "ERROR", "FINDING", "NOT_RUN"}:
                raise ValueError("trusted-artifact check has an unsupported status")
            check_id = str(item.get("id", "trusted-artifact"))
            summary = str(item.get("summary", "")).strip()
            label = f"Supply chain / {check_id}: {summary}" if summary else f"Supply chain / {check_id}"
            if status in {"FAIL", "ERROR"}:
                blockers.append(label)
            elif status in {"FINDING", "NOT_RUN"}:
                gaps.append(label)
            elif status == "PASS":
                strengths.append(label)
        if artifact_status in {"FAILED", "ERROR"}:
            blockers.append(f"Trusted artifact verification failed; observed {artifact_status}.")
        if artifact_status != "VERIFIED":
            gaps.append(f"Trusted artifact verification is incomplete; observed {artifact_status}.")
        if artifact_status == "VERIFIED":
            strengths.append("Trusted artifact: OCI SBOM/provenance and image-subject bindings verified.")
    elif require_trusted_artifact:
        blockers.append("Trusted artifact evidence is required but no trusted-artifact report was supplied.")
    else:
        gaps.append("Trusted artifact evidence was not supplied for this decision brief.")

    if require_trusted_artifact and artifact_status != "VERIFIED":
        blockers.append(f"Trusted artifact gate requires VERIFIED; observed {artifact_status}.")
    if require_scout and scout_status != "PASS":
        blockers.append(f"Docker Scout gate requires PASS; observed {scout_status}.")
    elif scout_status == "PASS":
        strengths.append("Docker Scout: configured policy evaluation passed for the observed artifact.")
    elif scout_status != "NOT_RUN":
        gaps.append(f"Docker Scout observed status: {scout_status}.")

    blocking_assurance = assurance.get("blocking_failures") if assurance else None
    if isinstance(blocking_assurance, int) and blocking_assurance > 0:
        blockers.append(f"Independent assurance reported {blocking_assurance} blocking failure(s).")
    elif assurance_status == "PASS":
        strengths.append("Independent post-run assurance completed without blocking failures.")
    elif assurance:
        gaps.append(f"Independent assurance status: {assurance_status}.")
    else:
        gaps.append("Independent assurance summary was not supplied.")

    blockers = list(dict.fromkeys(blockers))
    gaps = list(dict.fromkeys(gaps))
    strengths = list(dict.fromkeys(strengths))

    if blockers:
        decision = "BLOCKED"
    elif gaps:
        decision = "CONDITIONAL"
    else:
        decision = "EVIDENCE_READY"

    next_actions: list[str] = []
    if blockers:
        next_actions.append("Resolve blocking FAIL/ERROR evidence and re-run the exact PoC flow before approval.")
    if not counts or set(counts) == {"N/A"}:
        next_actions.append("Run an assessment with applicable controls and preserve its evidence before approval.")
    if counts.get("PARTIAL", 0) or counts.get("MANUAL", 0):
        next_actions.append("Convert priority PARTIAL/MANUAL controls into observed evidence or document explicit risk acceptance.")
    if artifact_status != "VERIFIED":
        next_actions.append("Run the trusted-artifact flow on the agent-modified workspace and verify BuildKit SBOM/provenance binding.")
    if scout_status != "PASS":
        next_actions.append("Evaluate Docker Scout policies in the target environment; use gate mode where policy failure must block promotion.")
    if assurance_status != "PASS":
        next_actions.append("Run post-assessment assurance and resolve any blocking integrity/authenticity verifier failure.")
    if not next_actions:
        next_actions.append("Preserve the signed evidence handoff and repeat the same protocol after material agent, policy, runtime or dependency changes.")

    return DecisionBrief(
        schema_version=1,
        generated_at=_utc_now(),
        decision=decision,
        assessment_run_id=str(assessment.get("run_id", "")),
        baseline_version=str(assessment.get("baseline_version", "")),
        assessment_counts=dict(sorted(counts.items())),
        trusted_artifact_status=artifact_status,
        scout_status=scout_status,
        assurance_status=assurance_status,
        blockers=blockers,
        evidence_gaps=gaps,
        observed_strengths=strengths,
        recommended_next_actions=next_actions,
        source_artifacts={},
        claims_boundary=(
            "This decision is a PoC evidence disposition, not production authorization, compliance certification, "
            "official Docker or Agent Baseline conformance, or a guarantee of security. BLOCKED reflects observed "
            "blocking evidence; CONDITIONAL reflects unresolved evidence gaps; EVIDENCE_READY means only that the "
            "supplied evidence set contains no blocking failure or declared gap under this decision policy."
        ),
    )


def _write_html(brief: DecisionBrief, path: Path) -> None:
    palette = {"BLOCKED": "#b42318", "CONDITIONAL": "#b54708", "EVIDENCE_READY": "#067647"}

    def cards(items: list[str], empty: str) -> str:
        values = items or [empty]
        return "".join(f"<li>{html.escape(value)}</li>" for value in values)

    decision_color = palette.get(brief.decision, "#344054")
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Customer Evidence Decision Brief</title><style>
:root{{--ink:#101828;--muted:#667085;--line:#e4e7ec;--bg:#f7f9fc;--navy:#0b1f3a}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,sans-serif}}.wrap{{max-width:1040px;margin:auto;padding:48px 24px 80px}}header{{background:linear-gradient(135deg,var(--navy),#164d8b);color:white;border-radius:20px;padding:34px}}h1{{font-size:38px;margin:6px 0 10px}}header p{{color:#dce7ff;max-width:790px}}.decision{{margin:22px 0;background:#fff;border:1px solid var(--line);border-left:8px solid {decision_color};border-radius:14px;padding:22px}}.decision strong{{font-size:30px;color:{decision_color}}}.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:20px 0}}.card,section{{background:#fff;border:1px solid var(--line);border-radius:14px;padding:18px}}.card span{{display:block;color:var(--muted);font-size:12px}}.card strong{{font-size:18px}}section{{margin:12px 0}}h2{{font-size:19px;margin:0 0 8px}}li{{margin:6px 0}}.notice{{background:#fff8e8;border:1px solid #f5d477;border-radius:12px;padding:14px 16px;margin-top:20px}}@media(max-width:760px){{.grid{{grid-template-columns:1fr}}h1{{font-size:30px}}}}</style></head><body><div class="wrap"><header><div>AGENT BASELINE EVIDENCE LAB</div><h1>Customer Evidence Decision Brief</h1><p>A concise decision layer over the assessment, trusted software-supply-chain evidence and independent assurance. No synthetic security score is used.</p></header><div class="decision"><span>PoC evidence disposition</span><br><strong>{html.escape(brief.decision)}</strong></div><div class="grid"><div class="card"><span>Assessment run</span><strong>{html.escape(brief.assessment_run_id)}</strong></div><div class="card"><span>Trusted artifact</span><strong>{html.escape(brief.trusted_artifact_status)}</strong></div><div class="card"><span>Assurance</span><strong>{html.escape(brief.assurance_status)}</strong></div></div><section><h2>Blocking evidence</h2><ul>{cards(brief.blockers, 'No blocking evidence in the supplied inputs.')}</ul></section><section><h2>Evidence gaps</h2><ul>{cards(brief.evidence_gaps, 'No declared evidence gaps in the supplied inputs.')}</ul></section><section><h2>Observed strengths</h2><ul>{cards(brief.observed_strengths, 'No positive evidence was supplied.')}</ul></section><section><h2>Recommended next actions</h2><ol>{cards(brief.recommended_next_actions, 'Repeat after material change.')}</ol></section><div class="notice"><strong>Claims boundary:</strong> {html.escape(brief.claims_boundary)}</div></div></body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")


def create_decision_brief(
    assessment_path: str | Path,
    *,
    trusted_artifact_path: str | Path | None = None,
    assurance_path: str | Path | None = None,
    output: str | Path = "reports/customer-decision-brief.json",
    html_output: str | Path = "reports/customer-decision-brief.html",
    require_trusted_artifact: bool = False,
    require_scout: bool = False,
) -> DecisionBrief:
    assessment_file = Path(assessment_path)
    trusted_file = Path(trusted_artifact_path) if trusted_artifact_path else None
    assurance_file = Path(assurance_path) if assurance_path else None
    brief = build_decision_brief(
        _load_json(assessment_file),
        trusted_artifact=_load_json(trusted_file) if trusted_file else None,
        assurance=_load_json(assurance_file) if assurance_file else None,
        require_trusted_artifact=require_trusted_artifact,
        require_scout=require_scout,
    )
    brief_data = brief.to_dict()
    brief_data["source_artifacts"] = {
        "assessment": str(assessment_file),
        "trusted_artifact": str(trusted_file) if trusted_file else "",
        "assurance": str(assurance_file) if assurance_file else "",
    }
    brief = DecisionBrief(**brief_data)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(brief.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_html(brief, Path(html_output))
    return brief


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a customer-facing evidence decision brief")
    parser.add_argument("assessment")
    parser.add_argument("--trusted-artifact", default=None)
    parser.add_argument("--assurance", default=None)
    parser.add_argument("--output", default="reports/customer-decision-brief.json")
    parser.add_argument("--html", default="reports/customer-decision-brief.html")
    parser.add_argument("--require-trusted-artifact", action="store_true")
    parser.add_argument("--require-scout", action="store_true")
    args = parser.parse_args(argv)
    try:
        brief = create_decision_brief(
            args.assessment,
            trusted_artifact_path=args.trusted_artifact,
            assurance_path=args.assurance,
            output=args.output,
            html_output=args.html,
            require_trusted_artifact=args.require_trusted_artifact,
            require_scout=args.require_scout,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print("CUSTOMER EVIDENCE DECISION")
    print(f"  decision: {brief.decision}")
    print(f"  blockers: {len(brief.blockers)}")
    print(f"  gaps:     {len(brief.evidence_gaps)}")
    return 1 if brief.decision == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())

