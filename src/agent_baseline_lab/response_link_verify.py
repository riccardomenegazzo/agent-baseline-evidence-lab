from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .evidence import sha256_file, verify_bundle
from .response_link import PREDICATE_TYPE
from .response_verify import verify_response_evidence


def _subject_digest(statement: dict[str, Any], prefix: str) -> str | None:
    for subject in statement.get("subject", []):
        if not isinstance(subject, dict):
            continue
        name = str(subject.get("name", ""))
        if name.startswith(prefix):
            digest = subject.get("digest", {})
            if isinstance(digest, dict):
                value = digest.get("sha256")
                if isinstance(value, str):
                    return value
    return None


def verify_response_link(
    statement_path: str | Path,
    assessment_evidence_dir: str | Path,
    response_evidence_path: str | Path,
) -> tuple[bool, list[str], dict[str, Any]]:
    statement_file = Path(statement_path)
    assessment_root = Path(assessment_evidence_dir)
    response_path = Path(response_evidence_path)
    errors: list[str] = []

    try:
        statement = json.loads(statement_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, [f"response-link statement cannot be parsed: {exc}"], {}

    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        errors.append("unexpected statement type")
    if statement.get("predicateType") != PREDICATE_TYPE:
        errors.append("unexpected response-link predicate type")

    bundle_ok, bundle_errors, bundle_summary = verify_bundle(assessment_root)
    errors.extend(f"assessment: {item}" for item in bundle_errors)

    assessment_path = assessment_root / "assessment.json"
    try:
        assessment = json.loads(assessment_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        assessment = {}
        errors.append(f"assessment.json cannot be parsed: {exc}")

    predicate = statement.get("predicate", {})
    if not isinstance(predicate, dict):
        predicate = {}
        errors.append("response-link predicate is not an object")

    run_id = str(assessment.get("run_id") or assessment_root.name)
    if predicate.get("assessmentRunId") != run_id:
        errors.append("assessment run ID does not match response-link predicate")
    if predicate.get("assessmentTraceHeadSha256") != bundle_summary.get("trace_head_sha256"):
        errors.append("assessment trace head does not match response-link predicate")

    manifest_path = assessment_root / "manifest.sha256.json"
    observed_manifest = sha256_file(manifest_path) if manifest_path.exists() else ""
    recorded_manifest = _subject_digest(statement, "assessment/")
    if recorded_manifest != observed_manifest:
        errors.append("assessment manifest digest does not match response-link subject")

    observed_response = sha256_file(response_path) if response_path.exists() else ""
    recorded_response = _subject_digest(statement, "response/")
    if recorded_response != observed_response:
        errors.append("response evidence digest does not match response-link subject")

    claims = predicate.get("claims", {})
    if not isinstance(claims, dict):
        claims = {}
        errors.append("response-link claims are not an object")
    expected_sandbox = str(predicate.get("sandbox", ""))
    require_revocation = bool(
        claims.get("sandboxScopedCredentialBindingRevocationVerified")
    )
    response_ok, response_errors, response_summary = verify_response_evidence(
        response_path,
        expected_sandbox=expected_sandbox,
        require_revocation=require_revocation,
    )
    errors.extend(f"response: {item}" for item in response_errors)

    if bool(claims.get("sandboxStopVerified")) != bool(
        response_summary.get("verified_stopped")
    ):
        errors.append("sandbox-stop claim does not match response evidence")
    if bool(claims.get("sandboxScopedCredentialBindingRevocationVerified")) != bool(
        response_summary.get("credential_revocation_tested")
    ):
        errors.append("credential-binding revocation claim does not match response evidence")

    summary = {
        "statement_sha256": sha256_file(statement_file) if statement_file.exists() else "",
        "assessment_bundle_verified": bundle_ok,
        "assessment_manifest_sha256": observed_manifest,
        "assessment_trace_head_sha256": bundle_summary.get("trace_head_sha256", ""),
        "response_evidence_sha256": observed_response,
        "response_evidence_verified": response_ok,
        "sandbox": expected_sandbox,
        "run_id": run_id,
    }
    return not errors, errors, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an assessment-to-response link statement")
    parser.add_argument("statement")
    parser.add_argument("assessment_evidence_dir")
    parser.add_argument("response_evidence")
    args = parser.parse_args(argv)
    ok, errors, summary = verify_response_link(
        args.statement,
        args.assessment_evidence_dir,
        args.response_evidence,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    for error in errors:
        print(error)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
