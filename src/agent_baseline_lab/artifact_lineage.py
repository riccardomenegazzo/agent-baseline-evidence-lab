from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .evidence import sha256_file
from .live_run import load_agent_run
from .oci_integrity import verify_oci_layout_integrity
from .trusted_artifact import verify_oci_attestations

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/agent-artifact-lineage/v1"


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _workspace_digest(root: Path) -> str:
    entries: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        entries.append((path.relative_to(root).as_posix(), sha256_file(path)))
    digest = hashlib.sha256()
    for rel, file_hash in entries:
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_hash.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"JSON input does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON input {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"JSON input must be an object: {path}")
    return payload


def _resolve_recorded(root: Path, value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def create_lineage_statement(
    session_path: str | Path,
    trusted_artifact_path: str | Path,
    *,
    root_path: str | Path = ".",
    output: str | Path = "reports/agent-artifact-lineage.json",
) -> dict[str, Any]:
    root = Path(root_path).resolve()
    session_file = Path(session_path)
    if not session_file.is_absolute():
        session_file = root / session_file
    trusted_file = Path(trusted_artifact_path)
    if not trusted_file.is_absolute():
        trusted_file = root / trusted_file

    session, session_verification = load_agent_run(session_file)
    if not session_verification.get("manifest_valid"):
        raise ValueError("agent-run evidence manifest is invalid")
    trusted = _load_json(trusted_file)
    if trusted.get("overall_status") != "VERIFIED":
        raise ValueError(
            "trusted artifact report must be VERIFIED before positive lineage can be created"
        )

    workspace_value = str(session.get("workspace", ""))
    trusted_context_value = str(trusted.get("context", ""))
    if not workspace_value or not trusted_context_value:
        raise ValueError("session workspace or trusted-artifact context is missing")
    workspace = _resolve_recorded(root, workspace_value)
    trusted_context = _resolve_recorded(root, trusted_context_value)
    if workspace != trusted_context:
        raise ValueError("trusted artifact context does not match the recorded agent workspace")
    if not workspace.is_dir():
        raise ValueError(f"agent workspace no longer exists: {workspace}")

    expected_workspace = str((session.get("workspace_after", {}) or {}).get("root_sha256", ""))
    observed_workspace = _workspace_digest(workspace)
    if not expected_workspace or observed_workspace != expected_workspace:
        raise ValueError("current workspace digest does not match the agent-run post-task snapshot")

    archive_value = str(trusted.get("oci_archive", ""))
    expected_archive = str(trusted.get("oci_archive_sha256", ""))
    if not archive_value or not expected_archive:
        raise ValueError("trusted artifact report does not contain an OCI archive digest")
    archive = _resolve_recorded(root, archive_value)
    if not archive.is_file():
        raise ValueError(f"trusted OCI archive is missing: {archive}")
    observed_archive = sha256_file(archive)
    if observed_archive != expected_archive:
        raise ValueError("trusted OCI archive digest does not match its report")

    graph_ok, graph_errors, graph_summary = verify_oci_layout_integrity(archive)
    if not graph_ok:
        raise ValueError(
            "trusted OCI archive failed recursive graph integrity verification: "
            + "; ".join(graph_errors)
        )
    oci_ok, oci_errors, oci_summary = verify_oci_attestations(archive)
    if not oci_ok:
        raise ValueError(
            "trusted OCI archive failed independent attestation verification: "
            + "; ".join(oci_errors)
        )

    task = session.get("task", {}) or {}
    execution = session.get("execution", {}) or {}
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": archive.name,
                "digest": {"sha256": observed_archive},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "schemaVersion": 1,
            "generatedAt": _utc_now(),
            "agentRun": {
                "sessionId": str(session.get("session_id", "")),
                "agent": str(session.get("agent", "")),
                "sandbox": str(session.get("sandbox_name", "")),
                "sessionSha256": sha256_file(session_file),
                "evidenceManifestVerified": True,
                "taskSha256": str(task.get("sha256", "")),
                "agentExecuted": bool(execution.get("attempted", False)),
                "agentReturncode": execution.get("returncode"),
            },
            "workspace": {
                "path": workspace_value,
                "postTaskSha256": observed_workspace,
                "matchesRecordedPostTaskSnapshot": True,
            },
            "artifact": {
                "trustedArtifactReportSha256": sha256_file(trusted_file),
                "ociArchive": archive_value,
                "ociArchiveSha256": observed_archive,
                "trustedArtifactStatus": str(trusted.get("overall_status", "")),
                "scoutStatus": str(trusted.get("scout_status", "")),
                "ociGraphIntegrityVerified": True,
                "verifiedBlobCount": graph_summary.get("verified_blob_count", 0),
                "ociAttestationsVerified": True,
                "predicateTypes": oci_summary.get("predicate_types", []),
                "subjectBindingsValid": oci_summary.get("subject_bindings_valid", False),
            },
            "claimsBoundary": (
                "This statement proves a local cryptographic linkage from one verified agent-run capsule and its "
                "unchanged post-task workspace to one independently verified OCI archive, including the referenced "
                "manifest/config/layer graph and SBOM/provenance subject bindings. It does not establish human/signer "
                "identity, source completeness, model intent, official Docker conformance, or artifact deployment."
            ),
        },
    }
    output_path = Path(output)
    if not output_path.is_absolute():
        output_path = root / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return statement


def verify_lineage_statement(
    statement_path: str | Path,
    session_path: str | Path,
    trusted_artifact_path: str | Path,
    *,
    root_path: str | Path = ".",
) -> tuple[bool, list[str], dict[str, Any]]:
    root = Path(root_path).resolve()
    statement_file = Path(statement_path)
    if not statement_file.is_absolute():
        statement_file = root / statement_file
    errors: list[str] = []
    regenerated_path = root / ".abl" / "lineage-verification.json"
    try:
        observed = _load_json(statement_file)
        expected = create_lineage_statement(
            session_path,
            trusted_artifact_path,
            root_path=root,
            output=regenerated_path,
        )
        observed_predicate = observed.get("predicate", {}) if isinstance(observed, dict) else {}
        expected_predicate = expected.get("predicate", {})
        for volatile in ("generatedAt",):
            if isinstance(observed_predicate, dict):
                observed_predicate.pop(volatile, None)
            if isinstance(expected_predicate, dict):
                expected_predicate.pop(volatile, None)
        if observed.get("_type") != STATEMENT_TYPE:
            errors.append("unexpected lineage statement type")
        if observed.get("predicateType") != PREDICATE_TYPE:
            errors.append("unexpected lineage predicate type")
        if observed.get("subject") != expected.get("subject"):
            errors.append("lineage subject does not match the current trusted OCI artifact")
        if observed_predicate != expected_predicate:
            errors.append("lineage predicate does not match current verified source evidence")
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    finally:
        regenerated_path.unlink(missing_ok=True)
    summary = {
        "verified": not errors,
        "statement_sha256": sha256_file(statement_file) if statement_file.is_file() else "",
        "errors": errors,
    }
    return not errors, errors, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bind a verified agent workspace to a trusted OCI artifact")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("session")
    create.add_argument("trusted_artifact")
    create.add_argument("--root", default=".")
    create.add_argument("--output", default="reports/agent-artifact-lineage.json")
    verify = sub.add_parser("verify")
    verify.add_argument("statement")
    verify.add_argument("session")
    verify.add_argument("trusted_artifact")
    verify.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            statement = create_lineage_statement(
                args.session,
                args.trusted_artifact,
                root_path=args.root,
                output=args.output,
            )
            print(f"Lineage created for OCI SHA-256 {statement['subject'][0]['digest']['sha256']}")
            return 0
        ok, errors, summary = verify_lineage_statement(
            args.statement,
            args.session,
            args.trusted_artifact,
            root_path=args.root,
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        if errors:
            for error in errors:
                print(error)
        return 0 if ok else 1
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
