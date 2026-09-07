from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .evidence import sha256_file, verify_bundle
from .response_verify import verify_response_evidence

PREDICATE_TYPE = "urn:agent-baseline-evidence-lab:response-link:v1"


def create_response_link(
    assessment_evidence_dir: str | Path,
    response_evidence_path: str | Path,
    output_path: str | Path,
    *,
    expected_sandbox: str,
    require_revocation: bool = False,
) -> dict[str, Any]:
    assessment_root = Path(assessment_evidence_dir)
    response_path = Path(response_evidence_path)

    bundle_ok, bundle_errors, bundle_summary = verify_bundle(assessment_root)
    if not bundle_ok:
        raise ValueError(
            "assessment evidence bundle is not internally valid: " + "; ".join(bundle_errors)
        )

    response_ok, response_errors, response_summary = verify_response_evidence(
        response_path,
        expected_sandbox=expected_sandbox,
        require_revocation=require_revocation,
    )
    if not response_ok:
        raise ValueError(
            "response evidence does not satisfy requested claims: " + "; ".join(response_errors)
        )

    assessment_path = assessment_root / "assessment.json"
    assessment = json.loads(assessment_path.read_text(encoding="utf-8"))
    run_id = str(assessment.get("run_id") or assessment_root.name)
    manifest_path = assessment_root / "manifest.sha256.json"

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": f"assessment/{run_id}/manifest.sha256.json",
                "digest": {"sha256": sha256_file(manifest_path)},
            },
            {
                "name": f"response/{response_path.name}",
                "digest": {"sha256": sha256_file(response_path)},
            },
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "createdAt": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "signed": False,
            "assessmentRunId": run_id,
            "assessmentTraceHeadSha256": bundle_summary.get("trace_head_sha256"),
            "sandbox": expected_sandbox,
            "claims": {
                "sandboxStopVerified": response_summary.get("verified_stopped") is True,
                "sandboxScopedCredentialBindingRevocationVerified": (
                    response_summary.get("credential_revocation_tested") is True
                ),
            },
            "credentialRevocationScope": response_summary.get("credential_revocation_scope"),
            "responseDrillId": response_summary.get("drill_id"),
            "claimsBoundary": (
                "Credential-binding revocation is Docker Sandbox scoped and does not prove "
                "upstream provider token invalidation or session revocation."
            ),
        },
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return statement


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Link a verified assessment bundle to verified response evidence by digest"
    )
    parser.add_argument("assessment_evidence_dir")
    parser.add_argument("response_evidence")
    parser.add_argument("--sandbox", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--require-revocation", action="store_true")
    args = parser.parse_args(argv)
    try:
        statement = create_response_link(
            args.assessment_evidence_dir,
            args.response_evidence,
            args.output,
            expected_sandbox=args.sandbox,
            require_revocation=args.require_revocation,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(statement, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
