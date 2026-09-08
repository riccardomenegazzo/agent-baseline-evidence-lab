from pathlib import Path

from agent_baseline_lab.customer_trust_flow import CustomerTrustFlowSummary
from agent_baseline_lab.demo_preflight import DemoPreflightCheck, DemoPreflightSummary
from agent_baseline_lab import trust_cli


def _preflight(ready: bool) -> DemoPreflightSummary:
    return DemoPreflightSummary(
        schema_version=1,
        scout_mode="observe",
        sandbox_smoke=False,
        ready=ready,
        required_failures=0 if ready else 1,
        checks=[
            DemoPreflightCheck(
                name="docker-daemon",
                status="PASS" if ready else "FAIL",
                required=True,
                detail="fixture",
                evidence={},
            )
        ],
        claims_boundary="fixture",
    )


def _flow(*, dry_run: bool) -> CustomerTrustFlowSummary:
    return CustomerTrustFlowSummary(
        schema_version=1,
        generated_at="2026-09-08T00:00:00+00:00",
        profile="community",
        dry_run=dry_run,
        scout_mode="observe",
        assessment_run_id="abl-test",
        agent_session_id="agent-test",
        trusted_artifact_status="DRY_RUN" if dry_run else "VERIFIED",
        scout_status="NOT_RUN" if dry_run else "PASS",
        lineage_created=not dry_run,
        lineage_verified=not dry_run,
        decision="CONDITIONAL",
        handoff_pack="reports/abl-test.customer-trust-handoff.zip",
        handoff_pack_sha256="a" * 64,
        handoff_verified=True,
        handoff_signature="reports/abl-test.customer-trust-handoff.zip.ed25519.json",
        handoff_signature_verified=True,
        public_key=".abl/keys/attestation-public.json",
        overall_status="DRY_RUN" if dry_run else "CONDITIONAL",
        claims_boundary="fixture",
    )


def test_dry_run_skips_host_preflight(monkeypatch):
    def fail_preflight(*args, **kwargs):
        raise AssertionError("dry-run must not probe the host")

    monkeypatch.setattr(trust_cli, "run_demo_preflight", fail_preflight)
    monkeypatch.setattr(
        trust_cli,
        "run_customer_trust_flow",
        lambda *args, **kwargs: _flow(dry_run=True),
    )

    assert trust_cli.main(["--dry-run"]) == 0


def test_live_run_fails_closed_when_preflight_is_not_ready(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(trust_cli, "run_demo_preflight", lambda *args, **kwargs: _preflight(False))

    def fail_flow(*args, **kwargs):
        raise AssertionError("live flow must not start after failed preflight")

    monkeypatch.setattr(trust_cli, "run_customer_trust_flow", fail_flow)
    output = tmp_path / "preflight.json"

    assert trust_cli.main(["--preflight-output", str(output)]) == 1
    assert output.is_file()


def test_preflight_only_never_starts_customer_flow(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(trust_cli, "run_demo_preflight", lambda *args, **kwargs: _preflight(True))

    def fail_flow(*args, **kwargs):
        raise AssertionError("preflight-only must not start customer flow")

    monkeypatch.setattr(trust_cli, "run_customer_trust_flow", fail_flow)
    output = tmp_path / "preflight.json"

    assert trust_cli.main(["--preflight-only", "--preflight-output", str(output)]) == 0
    assert output.is_file()
