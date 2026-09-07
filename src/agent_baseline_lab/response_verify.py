from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .response import load_response_drill


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_response_evidence(
    path: str | Path,
    *,
    expected_sandbox: str,
    require_stop: bool = True,
    require_revocation: bool = False,
) -> tuple[bool, list[str], dict]:
    evidence_path = Path(path)
    payload, errors = load_response_drill(evidence_path, expected_sandbox=expected_sandbox)
    if payload is None:
        return False, errors, {}
    if require_stop and payload.get("verified_stopped") is not True:
        errors.append("sandbox stop was not independently verified")
    if require_revocation and payload.get("credential_revocation_tested") is not True:
        errors.append("sandbox-scoped credential binding revocation was not verified")
    summary = {
        "evidence_path": str(evidence_path),
        "evidence_sha256": _sha256(evidence_path),
        "sandbox": payload.get("sandbox"),
        "verified_stopped": bool(payload.get("verified_stopped")),
        "credential_revocation_tested": bool(payload.get("credential_revocation_tested")),
        "credential_revocation_scope": payload.get("credential_revocation_scope"),
        "drill_id": payload.get("drill_id"),
    }
    return not errors, errors, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Agent Baseline response drill evidence")
    parser.add_argument("evidence")
    parser.add_argument("--sandbox", required=True)
    parser.add_argument("--require-revocation", action="store_true")
    args = parser.parse_args(argv)
    ok, errors, summary = verify_response_evidence(
        args.evidence,
        expected_sandbox=args.sandbox,
        require_revocation=args.require_revocation,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    for error in errors:
        print(error)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
