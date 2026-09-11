from __future__ import annotations

import argparse
import html
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .artifact_lineage import create_lineage_statement, verify_lineage_statement
from .decision_brief import create_decision_brief
from .evidence import sha256_file
from .golden_flow import run_golden_flow
from .privacy import find_local_path_markers, sanitize_text
from .sarif_export import export_sarif
from .signing import sign_file, validate_keypair, verify_signature
from .trust_handoff import create_handoff_pack, verify_handoff_pack, write_portable_json
from .trusted_artifact import run_trusted_artifact


@dataclass(frozen=True)
class CustomerTrustFlowSummary:
    schema_version: int
    generated_at: str
    profile: str
    dry_run: bool
    scout_mode: str
    assessment_run_id: str
    agent_session_id: str
    trusted_artifact_status: str
    scout_status: str
    lineage_created: bool
    lineage_verified: bool
    decision: str
    handoff_pack: str
    handoff_pack_sha256: str
    handoff_verified: bool
    handoff_signature: str
    handoff_signature_verified: bool
    public_key: str
    overall_status: str
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _portable(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return f"<external>/{path.name}"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON artifact {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"JSON artifact must contain an object: {path}")
    return payload


def _require_keys(root: Path) -> tuple[Path, Path]:
    private_key = root / ".abl" / "keys" / "attestation-private.json"
    public_key = root / ".abl" / "keys" / "attestation-public.json"
    if not private_key.is_file() or not public_key.is_file():
        raise ValueError(
            "customer trust flow requires a local Ed25519 keypair; run `make signing-keygen` first"
        )
    validate_keypair(private_key, public_key)
    return private_key, public_key


def _sign_and_verify(subject: Path, private_key: Path, public_key: Path) -> Path:
    signature = subject.with_name(subject.name + ".ed25519.json")
    sign_file(subject, private_key, signature)
    ok, errors, _ = verify_signature(subject, signature, public_key_path=public_key)
    if not ok:
        raise ValueError(f"signature verification failed for {subject.name}: " + "; ".join(errors))
    return signature


def _portable_text(source: Path, root: Path, output: Path) -> Path:
    text = source.read_text(encoding="utf-8", errors="replace")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(sanitize_text(text, root), encoding="utf-8")
    if find_local_path_markers(output.read_bytes(), root):
        raise ValueError(f"portable text still contains local path markers: {source}")
    return output


def _write_flow_html(
    path: Path,
    *,
    run_id: str,
    session_id: str,
    dry_run: bool,
    trusted_status: str,
    scout_status: str,
    lineage_verified: bool,
    decision: str,
) -> None:
    decision_color = {
        "BLOCKED": "#b42318",
        "CONDITIONAL": "#b54708",
        "EVIDENCE_READY": "#067647",
        "DRY_RUN": "#475467",
    }.get(decision, "#475467")
    lineage_label = "VERIFIED" if lineage_verified else ("NOT RUN" if dry_run else "NOT VERIFIED")
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Customer Trust Flow</title><style>
:root{{--ink:#101828;--muted:#667085;--line:#e4e7ec;--bg:#f7f9fc;--navy:#0b1f3a}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,sans-serif}}.wrap{{max-width:1050px;margin:auto;padding:48px 24px 80px}}header{{background:linear-gradient(135deg,var(--navy),#164d8b);color:white;border-radius:20px;padding:34px}}h1{{font-size:38px;margin:6px 0 12px}}header p{{color:#dce7ff;max-width:820px}}.decision{{margin:22px 0;background:white;border:1px solid var(--line);border-left:8px solid {decision_color};border-radius:14px;padding:20px}}.decision strong{{font-size:30px;color:{decision_color}}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}.card{{background:white;border:1px solid var(--line);border-radius:14px;padding:17px}}.card span{{display:block;color:var(--muted);font-size:12px}}.card strong{{font-size:17px;overflow-wrap:anywhere}}.flow{{background:white;border:1px solid var(--line);border-radius:14px;padding:22px;margin-top:20px;font-family:ui-monospace,monospace;white-space:pre-wrap}}.notice{{background:#fff8e8;border:1px solid #f5d477;border-radius:12px;padding:14px 16px;margin-top:20px}}@media(max-width:780px){{.grid{{grid-template-columns:repeat(2,1fr)}}h1{{font-size:30px}}}}</style></head><body><div class="wrap"><header><div>AGENT BASELINE EVIDENCE LAB</div><h1>Customer Trust Flow</h1><p>One evidence lifecycle from AI coding-agent execution through governance assessment, trusted container artifact, lineage, decision and signed customer handoff.</p></header><div class="decision"><span>Evidence disposition</span><br><strong>{html.escape(decision)}</strong></div><div class="grid"><div class="card"><span>Assessment</span><strong>{html.escape(run_id)}</strong></div><div class="card"><span>Agent session</span><strong>{html.escape(session_id)}</strong></div><div class="card"><span>Trusted artifact</span><strong>{html.escape(trusted_status)}</strong></div><div class="card"><span>Docker Scout</span><strong>{html.escape(scout_status)}</strong></div></div><div class="flow">AI coding task\n      ↓\nDocker Sandbox / governed execution\n      ↓\nAgent Baseline evidence + independent assurance\n      ↓\nBuildx OCI artifact + SBOM + provenance\n      ↓\nOCI graph + attestation verification\n      ↓\nAgent → workspace → artifact lineage: {html.escape(lineage_label)}\n      ↓\nDecision brief + SARIF\n      ↓\nSigned customer trust handoff</div><div class="notice"><strong>Claims boundary:</strong> This is run-specific PoC evidence. It is not official Docker certification, production authorization, signer identity proof, or a guarantee that an artifact is vulnerability-free.</div></div></body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")


def run_customer_trust_flow(
    root_path: str | Path = ".",
    *,
    profile: str = "community",
    baseline_cache: str | Path = ".cache/agentbaseline",
    dry_run: bool = False,
    scout_mode: str = "observe",
    cleanup: bool = True,
) -> CustomerTrustFlowSummary:
    if profile not in {"community", "mcp"}:
        raise ValueError("profile must be 'community' or 'mcp'")
    if scout_mode not in {"off", "observe", "gate"}:
        raise ValueError("scout_mode must be one of: off, observe, gate")

    root = Path(root_path).resolve()
    private_key, public_key = _require_keys(root)

    golden = run_golden_flow(
        root,
        profile=profile,
        baseline_cache=baseline_cache,
        dry_run=dry_run,
        cleanup=cleanup,
    )
    run_id = golden.assessment_run_id
    demo_path = root / "reports" / f"{run_id}.interview-demo.json"
    demo = _load_json(demo_path)
    session_id = str(demo.get("session_id", ""))
    if not session_id:
        raise ValueError("golden flow did not record an agent session id")
    session_path = root / "agent-runs" / session_id / "session.json"
    session = _load_json(session_path)
    workspace_ref = str(session.get("workspace", ""))
    if not workspace_ref:
        raise ValueError("agent session does not record a workspace")
    workspace = root / workspace_ref

    trust_dir = root / "reports" / f"{run_id}.trust"
    trusted_dir = trust_dir / "trusted-artifact"
    trusted = run_trusted_artifact(
        workspace,
        output_root=root,
        output_dir=trusted_dir,
        dry_run=dry_run,
        scout_mode="off" if dry_run else scout_mode,
    )
    trusted_raw = trusted_dir / "trusted-artifact.json"
    trusted_portable = trust_dir / "trusted-artifact.portable.json"
    write_portable_json(trusted_raw, root_path=root, output=trusted_portable)
    trusted_signature = _sign_and_verify(trusted_portable, private_key, public_key)

    # Preserve useful machine-readable BuildKit/Scout evidence without exporting host paths.
    supplemental_sources: list[tuple[str, Path, str]] = []
    raw_trusted_payload = _load_json(trusted_raw)
    supplemental_roles = {
        "build_metadata": ("buildkit-metadata", "supply-chain/build-metadata.json"),
        "scout_result": ("docker-scout-policy-result", "supply-chain/scout-policy-result.json"),
        "scout_sarif": ("docker-scout-sarif", "integrations/docker-scout.sarif"),
    }
    for field, (role, archive_name) in supplemental_roles.items():
        value = str(raw_trusted_payload.get(field, ""))
        if not value:
            continue
        source = root / value
        if not source.is_file():
            continue
        portable = trust_dir / f"portable-{source.name}"
        write_portable_json(source, root_path=root, output=portable)
        supplemental_sources.append((role, portable, archive_name))
    scout_report_value = str(raw_trusted_payload.get("scout_report", ""))
    if scout_report_value:
        scout_report_source = root / scout_report_value
        if scout_report_source.is_file():
            scout_report_portable = trust_dir / "scout-policy.txt"
            _portable_text(scout_report_source, root, scout_report_portable)
            supplemental_sources.append(
                ("docker-scout-policy-report", scout_report_portable, "supply-chain/scout-policy.txt")
            )

    lineage_path = trust_dir / "agent-artifact-lineage.json"
    lineage_signature: Path | None = None
    lineage_created = False
    lineage_verified = False
    if not dry_run and trusted.overall_status == "VERIFIED":
        create_lineage_statement(
            session_path,
            trusted_portable,
            root_path=root,
            output=lineage_path,
        )
        lineage_created = True
        lineage_verified, lineage_errors, _ = verify_lineage_statement(
            lineage_path,
            session_path,
            trusted_portable,
            root_path=root,
        )
        if not lineage_verified:
            raise ValueError("agent-artifact lineage verification failed: " + "; ".join(lineage_errors))
        lineage_signature = _sign_and_verify(lineage_path, private_key, public_key)

    assessment = root / "reports" / f"{run_id}.json"
    assurance = root / "reports" / "assurance-summary.json"
    decision_raw = trust_dir / "customer-decision.json"
    decision_html_raw = trust_dir / "customer-decision.html"
    brief = create_decision_brief(
        assessment,
        trusted_artifact_path=trusted_portable,
        assurance_path=assurance,
        output=decision_raw,
        html_output=decision_html_raw,
        require_trusted_artifact=not dry_run,
        require_scout=(not dry_run and scout_mode == "gate"),
    )
    decision_portable = trust_dir / "customer-decision.portable.json"
    write_portable_json(decision_raw, root_path=root, output=decision_portable)
    decision_signature = _sign_and_verify(decision_portable, private_key, public_key)
    decision_html = trust_dir / "customer-decision.portable.html"
    _portable_text(decision_html_raw, root, decision_html)

    sarif_path = trust_dir / "agent-governance.sarif"
    export_sarif(
        assessment,
        trusted_artifact_path=trusted_portable,
        output=sarif_path,
    )

    disposition = "DRY_RUN" if dry_run else brief.decision
    if not dry_run and not lineage_verified:
        disposition = "BLOCKED"

    flow_html = trust_dir / "customer-trust-flow.html"
    _write_flow_html(
        flow_html,
        run_id=run_id,
        session_id=session_id,
        dry_run=dry_run,
        trusted_status=trusted.overall_status,
        scout_status=trusted.scout_status,
        lineage_verified=lineage_verified,
        decision=disposition,
    )

    golden_summary = root / "reports" / f"{run_id}.golden-flow.json"
    golden_pack = root / golden.customer_pack
    golden_pack_signature = root / golden.customer_pack_signature
    sources: list[tuple[str, Path, str]] = [
        ("golden-flow-summary", golden_summary, "governance/golden-flow.json"),
        ("golden-customer-pack", golden_pack, "evidence/customer-evidence-pack.zip"),
        (
            "golden-customer-pack-signature",
            golden_pack_signature,
            "evidence/customer-evidence-pack.zip.ed25519.json",
        ),
        ("public-verification-key", public_key, "trust/attestation-public.json"),
        ("trusted-artifact", trusted_portable, "supply-chain/trusted-artifact.json"),
        (
            "trusted-artifact-signature",
            trusted_signature,
            "supply-chain/trusted-artifact.ed25519.json",
        ),
        ("customer-decision", decision_portable, "decision/customer-decision.json"),
        ("customer-decision-html", decision_html, "decision/customer-decision.html"),
        (
            "customer-decision-signature",
            decision_signature,
            "decision/customer-decision.ed25519.json",
        ),
        ("agent-governance-sarif", sarif_path, "integrations/agent-governance.sarif"),
        ("customer-trust-flow-html", flow_html, "customer-trust-flow.html"),
        *supplemental_sources,
    ]
    if lineage_created and lineage_signature is not None:
        sources.extend(
            [
                ("agent-artifact-lineage", lineage_path, "lineage/agent-artifact-lineage.json"),
                (
                    "agent-artifact-lineage-signature",
                    lineage_signature,
                    "lineage/agent-artifact-lineage.ed25519.json",
                ),
            ]
        )

    handoff = root / "reports" / f"{run_id}.customer-trust-handoff.zip"
    create_handoff_pack(
        root,
        run_id=run_id,
        output_path=handoff,
        dry_run=dry_run,
        sources=sources,
    )
    handoff_ok, handoff_errors, _ = verify_handoff_pack(handoff)
    if not handoff_ok:
        raise ValueError("customer trust handoff verification failed: " + "; ".join(handoff_errors))
    handoff_signature = _sign_and_verify(handoff, private_key, public_key)

    overall = disposition
    summary = CustomerTrustFlowSummary(
        schema_version=1,
        generated_at=_utc_now(),
        profile=profile,
        dry_run=dry_run,
        scout_mode=scout_mode,
        assessment_run_id=run_id,
        agent_session_id=session_id,
        trusted_artifact_status=trusted.overall_status,
        scout_status=trusted.scout_status,
        lineage_created=lineage_created,
        lineage_verified=lineage_verified,
        decision=brief.decision,
        handoff_pack=_portable(root, handoff),
        handoff_pack_sha256=sha256_file(handoff),
        handoff_verified=handoff_ok,
        handoff_signature=_portable(root, handoff_signature),
        handoff_signature_verified=True,
        public_key=_portable(root, public_key),
        overall_status=overall,
        claims_boundary=(
            "The customer trust flow composes run-specific evidence from governed agent execution, assessment, "
            "post-run assurance, trusted OCI artifact verification, optional Docker Scout policy evaluation, "
            "agent-to-artifact lineage and signed handoff packaging. Dry-run deliberately cannot claim live "
            "containment or artifact lineage. EVIDENCE_READY is an evidence disposition, not production approval, "
            "official Docker certification, compliance certification, signer identity proof, or a security guarantee."
        ),
    )
    summary_path = root / "reports" / f"{run_id}.customer-trust-flow.json"
    summary_path.write_text(
        json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the complete customer trust lifecycle")
    parser.add_argument("--root", default=".")
    parser.add_argument("--profile", choices=["community", "mcp"], default="community")
    parser.add_argument("--baseline-cache", default=".cache/agentbaseline")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--scout-mode", choices=["off", "observe", "gate"], default="observe")
    parser.add_argument("--no-cleanup", action="store_true")
    args = parser.parse_args(argv)
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


if __name__ == "__main__":
    raise SystemExit(main())

