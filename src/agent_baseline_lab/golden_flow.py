from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .assurance_suite import run_assurance_suite
from .evidence import sha256_file
from .interview_demo import run_interview_demo
from .portable_pack import create_pack, verify_pack
from .readiness import run_readiness
from .signing import sign_file, validate_keypair, verify_signature


@dataclass(frozen=True)
class GoldenFlowSummary:
    schema_version: int
    generated_at: str
    profile: str
    dry_run: bool
    readiness_checked: bool
    readiness_ready: bool | None
    baseline_signature_checked: bool
    baseline_signature_verified: bool | None
    assessment_run_id: str
    assessment_bundle_verified: bool
    response_link_verified: bool
    quarantine_registered: bool
    incident_bundle_verified: bool
    attestation_signature_verified: bool
    assurance_status: str
    assurance_blocking_failures: int
    customer_pack: str
    customer_pack_sha256: str
    customer_pack_verified: bool
    customer_pack_signature: str
    customer_pack_signature_verified: bool
    public_key: str
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


def _require_signing_keys(root: Path) -> tuple[Path, Path]:
    private_key = root / ".abl" / "keys" / "attestation-private.json"
    public_key = root / ".abl" / "keys" / "attestation-public.json"
    missing = [str(path.relative_to(root)) for path in (private_key, public_key) if not path.is_file()]
    if missing:
        raise ValueError(
            "golden flow requires an existing local Ed25519 keypair; run `make signing-keygen` first. "
            "Missing: " + ", ".join(missing)
        )
    validate_keypair(private_key, public_key)
    return private_key, public_key


def _baseline_paths(root: Path, baseline_cache: str | Path) -> tuple[Path, Path]:
    cache = Path(baseline_cache)
    if not cache.is_absolute():
        cache = root / cache
    return cache / "baseline.lock.json", cache / "baseline.lock.ed25519.json"


def run_golden_flow(
    root_path: str | Path = ".",
    *,
    profile: str = "community",
    baseline_cache: str | Path = ".cache/agentbaseline",
    dry_run: bool = False,
    cleanup: bool = True,
) -> GoldenFlowSummary:
    if profile not in {"community", "mcp"}:
        raise ValueError("profile must be 'community' or 'mcp'")

    root = Path(root_path).resolve()
    private_key, public_key = _require_signing_keys(root)

    readiness_checked = not dry_run
    readiness_ready: bool | None = None
    baseline_signature_checked = not dry_run
    baseline_signature_verified: bool | None = None
    if readiness_checked:
        readiness = run_readiness(root, profile=profile, baseline_cache=baseline_cache)
        readiness_ready = readiness.ready
        readiness_path = root / "reports" / f"golden-readiness-{profile}.json"
        readiness_path.parent.mkdir(parents=True, exist_ok=True)
        readiness_path.write_text(
            json.dumps(readiness.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if not readiness.ready:
            failures = [
                check.name
                for check in readiness.checks
                if check.required and check.status != "PASS"
            ]
            raise ValueError("golden flow readiness failed: " + ", ".join(failures))

        baseline_lock, baseline_signature = _baseline_paths(root, baseline_cache)
        if not baseline_signature.is_file():
            raise ValueError(
                "golden flow requires a signed baseline lock; run `make baseline-lock-sign` first"
            )
        baseline_signature_verified, baseline_errors, _ = verify_signature(
            baseline_lock,
            baseline_signature,
            public_key_path=public_key,
        )
        if not baseline_signature_verified:
            raise ValueError(
                "baseline lock signature verification failed: " + "; ".join(baseline_errors)
            )

    config = root / "examples" / ("agent-mcp.yaml" if profile == "mcp" else "agent.yaml")
    task = root / "examples" / ("task-mcp.md" if profile == "mcp" else "task.md")
    demo = run_interview_demo(
        config,
        task,
        output_root=root,
        dry_run=dry_run,
        enable_audit=profile == "mcp",
        cleanup=cleanup and not dry_run,
    )
    run_id = demo.assessment_run_id

    attestation = root / "reports" / f"{run_id}.attestation.json"
    attestation_signature = root / "reports" / f"{run_id}.attestation.json.ed25519.json"
    sign_file(attestation, private_key, attestation_signature)
    attestation_ok, attestation_errors, _ = verify_signature(
        attestation,
        attestation_signature,
        public_key_path=public_key,
    )
    if not attestation_ok:
        raise ValueError("attestation signature verification failed: " + "; ".join(attestation_errors))

    assurance = run_assurance_suite(root)
    if assurance.assessment_run_id != run_id:
        raise ValueError(
            f"assurance selected unexpected assessment {assurance.assessment_run_id}; expected {run_id}"
        )
    assurance_path = root / "reports" / "assurance-summary.json"
    assurance_path.write_text(
        json.dumps(assurance.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if assurance.blocking_failures:
        raise ValueError(f"assurance suite reported {assurance.blocking_failures} blocking failure(s)")

    pack = root / "reports" / f"{run_id}.customer-evidence-pack.zip"
    create_pack(root, output_path=pack, run_id=run_id)
    pack_ok, pack_errors, _ = verify_pack(pack)
    if not pack_ok:
        raise ValueError("portable customer pack verification failed: " + "; ".join(pack_errors))

    pack_signature = root / "reports" / f"{run_id}.customer-evidence-pack.zip.ed25519.json"
    sign_file(pack, private_key, pack_signature)
    pack_signature_ok, pack_signature_errors, _ = verify_signature(
        pack,
        pack_signature,
        public_key_path=public_key,
    )
    if not pack_signature_ok:
        raise ValueError(
            "customer pack signature verification failed: " + "; ".join(pack_signature_errors)
        )

    summary = GoldenFlowSummary(
        schema_version=1,
        generated_at=_utc_now(),
        profile=profile,
        dry_run=dry_run,
        readiness_checked=readiness_checked,
        readiness_ready=readiness_ready,
        baseline_signature_checked=baseline_signature_checked,
        baseline_signature_verified=baseline_signature_verified,
        assessment_run_id=run_id,
        assessment_bundle_verified=demo.assessment_bundle_verified,
        response_link_verified=demo.response_link_verified,
        quarantine_registered=demo.quarantine_registered,
        incident_bundle_verified=demo.incident_bundle_verified,
        attestation_signature_verified=attestation_ok,
        assurance_status=assurance.overall_status,
        assurance_blocking_failures=assurance.blocking_failures,
        customer_pack=_portable(root, pack),
        customer_pack_sha256=sha256_file(pack),
        customer_pack_verified=pack_ok,
        customer_pack_signature=_portable(root, pack_signature),
        customer_pack_signature_verified=pack_signature_ok,
        public_key=_portable(root, public_key),
        claims_boundary=(
            "The golden flow proves only the checks actually executed for this run. The live path verifies "
            "the signed baseline lock before execution. A valid Ed25519 signature proves possession of the "
            "configured local private key, not external organizational identity. Dry-run mode intentionally "
            "skips Docker readiness and baseline-signature gating and cannot claim live containment, credential "
            "revocation, quarantine, incident response, or Docker AI Governance coverage."
        ),
    )
    summary_path = root / "reports" / f"{run_id}.golden-flow.json"
    summary_path.write_text(
        json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the complete customer-ready evidence lifecycle")
    parser.add_argument("--root", default=".")
    parser.add_argument("--profile", choices=["community", "mcp"], default="community")
    parser.add_argument("--baseline-cache", default=".cache/agentbaseline")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-cleanup", action="store_true")
    args = parser.parse_args(argv)
    try:
        summary = run_golden_flow(
            args.root,
            profile=args.profile,
            baseline_cache=args.baseline_cache,
            dry_run=args.dry_run,
            cleanup=not args.no_cleanup,
        )
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    print("GOLDEN CUSTOMER EVIDENCE FLOW")
    print(f"  profile:              {summary.profile}")
    print(f"  assessment run:       {summary.assessment_run_id}")
    print(f"  readiness checked:    {summary.readiness_checked}")
    print(f"  readiness ready:      {summary.readiness_ready}")
    print(f"  baseline signed:      {summary.baseline_signature_verified}")
    print(f"  bundle verified:      {summary.assessment_bundle_verified}")
    print(f"  response linked:      {summary.response_link_verified}")
    print(f"  quarantine:           {summary.quarantine_registered}")
    print(f"  incident bundle:      {summary.incident_bundle_verified}")
    print(f"  attestation signed:   {summary.attestation_signature_verified}")
    print(f"  assurance:            {summary.assurance_status}")
    print(f"  customer pack:        {summary.customer_pack}")
    print(f"  pack SHA-256:         {summary.customer_pack_sha256}")
    print(f"  pack signature valid: {summary.customer_pack_signature_verified}")

    if summary.assurance_blocking_failures:
        return 1
    if not summary.assessment_bundle_verified:
        return 1
    if not summary.attestation_signature_verified:
        return 1
    if not summary.customer_pack_verified or not summary.customer_pack_signature_verified:
        return 1
    if not summary.dry_run:
        if summary.readiness_ready is not True:
            return 1
        if summary.baseline_signature_verified is not True:
            return 1
        if not summary.response_link_verified:
            return 1
        if not summary.quarantine_registered or not summary.incident_bundle_verified:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

