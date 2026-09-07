from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .engine import run_assessment
from .evidence import sha256_file, verify_bundle
from .live_run import cleanup_sandbox, run_agent_task
from .models import Status
from .response import run_stop_drill
from .response_link import create_response_link
from .response_link_verify import verify_response_link


@dataclass(frozen=True)
class InterviewDemoSummary:
    schema_version: int
    started_at: str
    completed_at: str
    session_id: str
    sandbox: str
    assessment_run_id: str
    assessment_json: str
    assessment_html: str
    assessment_evidence: str
    response_evidence: str
    response_link: str
    response_link_sha256: str
    assessment_bundle_verified: bool
    response_link_verified: bool
    agent_executed: bool
    agent_returncode: int | None
    assessment_fail_or_error_count: int
    sandbox_stop_verified: bool
    credential_binding_revocation_verified: bool
    cleanup_attempted: bool
    cleanup_succeeded: bool | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def run_interview_demo(
    config_path: str | Path,
    task_path: str | Path,
    *,
    output_root: str | Path = ".",
    timeout: int = 900,
    dry_run: bool = False,
    enable_audit: bool = False,
    cleanup: bool = False,
) -> InterviewDemoSummary:
    started_at = _utc_now()
    root = Path(output_root).resolve()

    live = run_agent_task(
        config_path,
        task_path,
        output_root=root,
        timeout=timeout,
        dry_run=dry_run,
        capture_output=False,
        enable_audit=enable_audit,
    )

    report, assessment_json, assessment_html = run_assessment(
        live.config_for_assessment,
        root,
    )
    assessment_evidence = root / "evidence" / report.run_id
    bundle_ok, bundle_errors, _ = verify_bundle(assessment_evidence)
    if not bundle_ok:
        raise RuntimeError(
            "assessment evidence verification failed: " + "; ".join(bundle_errors)
        )

    response_dir = root / ".abl" / "response"
    response_path = response_dir / f"{live.session_id}.json"
    response = run_stop_drill(
        live.sandbox_name,
        response_path,
        dry_run=dry_run,
        test_disposable_secret_revocation=not dry_run,
    )

    link_path = root / "reports" / f"{report.run_id}.response-link.json"
    if dry_run:
        # A dry run is intentionally incapable of satisfying containment claims.
        # Preserve the negative evidence but do not fabricate a response link.
        link_verified = False
        link_sha256 = ""
    else:
        create_response_link(
            assessment_evidence,
            response_path,
            link_path,
            expected_sandbox=live.sandbox_name,
            require_revocation=True,
        )
        link_ok, link_errors, _ = verify_response_link(
            link_path,
            assessment_evidence,
            response_path,
        )
        if not link_ok:
            raise RuntimeError(
                "response-link verification failed: " + "; ".join(link_errors)
            )
        link_verified = True
        link_sha256 = sha256_file(link_path)

    cleanup_attempted = False
    cleanup_succeeded: bool | None = None
    if cleanup and live.executed:
        cleanup_attempted = True
        cleanup_result = cleanup_sandbox(live.sandbox_name)
        cleanup_succeeded = cleanup_result.ok

    fail_or_error = sum(
        result.status in {Status.FAIL, Status.ERROR} for result in report.results
    )
    summary = InterviewDemoSummary(
        schema_version=1,
        started_at=started_at,
        completed_at=_utc_now(),
        session_id=live.session_id,
        sandbox=live.sandbox_name,
        assessment_run_id=report.run_id,
        assessment_json=str(assessment_json),
        assessment_html=str(assessment_html),
        assessment_evidence=str(assessment_evidence),
        response_evidence=str(response_path),
        response_link=str(link_path) if not dry_run else "",
        response_link_sha256=link_sha256,
        assessment_bundle_verified=bundle_ok,
        response_link_verified=link_verified,
        agent_executed=live.executed,
        agent_returncode=live.returncode,
        assessment_fail_or_error_count=fail_or_error,
        sandbox_stop_verified=response.verified_stopped,
        credential_binding_revocation_verified=response.credential_revocation_tested,
        cleanup_attempted=cleanup_attempted,
        cleanup_succeeded=cleanup_succeeded,
    )

    summary_path = root / "reports" / f"{report.run_id}.interview-demo.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the complete Agent Baseline manager-facing evidence flow"
    )
    parser.add_argument("--config", default="examples/agent.yaml")
    parser.add_argument("--task", default="examples/task.md")
    parser.add_argument("--output", default=".")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--with-docker-audit", action="store_true")
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="remove the unique disposable sandbox after all response evidence is verified",
    )
    args = parser.parse_args(argv)

    try:
        summary = run_interview_demo(
            args.config,
            args.task,
            output_root=args.output,
            timeout=args.timeout,
            dry_run=args.dry_run,
            enable_audit=args.with_docker_audit,
            cleanup=args.cleanup,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))

    print("INTERVIEW EVIDENCE FLOW")
    print(f"  session:             {summary.session_id}")
    print(f"  sandbox:             {summary.sandbox}")
    print(f"  assessment run:      {summary.assessment_run_id}")
    print(f"  bundle verified:     {summary.assessment_bundle_verified}")
    print(f"  stop verified:       {summary.sandbox_stop_verified}")
    print(
        "  credential revoked: "
        f"{summary.credential_binding_revocation_verified} (Docker sandbox binding)"
    )
    print(f"  response link:       {summary.response_link_verified}")
    if summary.response_link_sha256:
        print(f"  response link SHA:   {summary.response_link_sha256}")
    if summary.cleanup_attempted:
        print(f"  cleanup succeeded:   {summary.cleanup_succeeded}")
    print(f"  HTML report:         {summary.assessment_html}")

    if args.dry_run:
        return 0
    if summary.agent_returncode not in (None, 0):
        return 1
    if not summary.assessment_bundle_verified or not summary.response_link_verified:
        return 1
    if not summary.sandbox_stop_verified:
        return 1
    if not summary.credential_binding_revocation_verified:
        return 1
    if summary.cleanup_attempted and summary.cleanup_succeeded is not True:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
