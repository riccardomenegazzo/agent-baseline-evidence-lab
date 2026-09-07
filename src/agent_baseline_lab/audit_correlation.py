from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .audit import load_audit_records
from .commands import exists, run
from .evidence import sha256_file


@dataclass(frozen=True)
class CorrelationProbe:
    schema_version: int
    session_id: str
    sandbox: str
    marker_host: str
    attempted: bool
    returncode: int | None
    stdout_sha256: str
    stderr_sha256: str
    expected_network_result: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuditCorrelationResult:
    schema_version: int
    session_id: str
    marker_host: str
    strength: str
    exact_marker_match: bool
    matched_event_ids: list[str]
    matched_audit_session_ids: list[str]
    candidate_audit_session_ids: list[str]
    records_selected: int
    in_progress_files: int
    source_path: str
    agent: str
    since: str
    until: str
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def marker_for_session(session_id: str) -> str:
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:20]
    return f"abl-{digest}.correlation.invalid"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def run_correlation_probe(
    sandbox: str,
    session_id: str,
    output_path: str | Path,
    *,
    dry_run: bool = False,
) -> CorrelationProbe:
    marker = marker_for_session(session_id)
    if dry_run or not exists("sbx"):
        result = CorrelationProbe(
            schema_version=1,
            session_id=session_id,
            sandbox=sandbox,
            marker_host=marker,
            attempted=False,
            returncode=None,
            stdout_sha256=_sha256_text(""),
            stderr_sha256=_sha256_text(""),
            expected_network_result="blocked-or-unreachable",
        )
    else:
        # Use a reserved .invalid hostname. We want a governance-visible network
        # attempt, not a successful external connection. Curl is preferred; Python
        # socket is a fallback for development sandboxes without curl.
        script = (
            "if command -v curl >/dev/null 2>&1; then "
            f"curl -fsS --connect-timeout 2 https://{marker}/ >/dev/null 2>&1; "
            "elif command -v python3 >/dev/null 2>&1; then "
            "python3 -c \"import socket; "
            f"socket.create_connection(('{marker}',443),2)\" >/dev/null 2>&1; "
            "else exit 127; fi"
        )
        command = run(["sbx", "exec", sandbox, "sh", "-lc", script], timeout=15)
        result = CorrelationProbe(
            schema_version=1,
            session_id=session_id,
            sandbox=sandbox,
            marker_host=marker,
            attempted=True,
            returncode=command.returncode,
            stdout_sha256=_sha256_text(command.stdout),
            stderr_sha256=_sha256_text(command.stderr),
            expected_network_result="blocked-or-unreachable",
        )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def analyze_audit_correlation(
    *,
    session_id: str,
    marker_host: str,
    agent: str,
    since: str,
    until: str,
    source: str | Path | None = None,
) -> AuditCorrelationResult:
    records, summary = load_audit_records(
        source,
        agent=agent or None,
        since=since or None,
        until=until or None,
        redaction_salt=session_id,
    )
    matches = [
        record
        for record in records
        if marker_host in str(record.get("resource_id", ""))
    ]
    matched_event_ids = sorted(
        {
            str(record.get("audit_event_id"))
            for record in matches
            if record.get("audit_event_id")
        }
    )
    matched_sessions = sorted(
        {
            str(record.get("audit_session_id"))
            for record in matches
            if record.get("audit_session_id")
        }
    )
    candidates = summary.audit_session_ids

    if matches:
        strength = "exact-marker"
    elif not records and summary.in_progress_files:
        strength = "pending-finalization"
    elif len(candidates) == 1:
        strength = "single-daemon-session"
    elif len(candidates) > 1:
        strength = "ambiguous-multi-session"
    else:
        strength = "no-observed-correlation"

    return AuditCorrelationResult(
        schema_version=1,
        session_id=session_id,
        marker_host=marker_host,
        strength=strength,
        exact_marker_match=bool(matches),
        matched_event_ids=matched_event_ids,
        matched_audit_session_ids=matched_sessions,
        candidate_audit_session_ids=candidates,
        records_selected=summary.records_selected,
        in_progress_files=summary.in_progress_files,
        source_path=summary.source_path,
        agent=agent,
        since=since,
        until=until,
        claims_boundary=(
            "Only exact-marker means a Docker audit resource_id contained the run-scoped marker. "
            "A single daemon session is bounded supporting evidence, not proof that every event "
            "belongs to this coding task."
        ),
    )


def correlate_session(
    session_path: str | Path,
    *,
    source: str | Path | None = None,
    output_path: str | Path | None = None,
) -> tuple[AuditCorrelationResult, Path]:
    path = Path(session_path)
    if path.is_dir():
        path = path / "session.json"
    session = json.loads(path.read_text(encoding="utf-8"))
    session_id = str(session.get("session_id", ""))
    if not session_id:
        raise ValueError("agent session does not contain session_id")
    agent = str(session.get("agent", ""))
    since = str(session.get("started_at", ""))
    until = datetime.now(UTC).replace(microsecond=0).isoformat()
    marker = marker_for_session(session_id)
    result = analyze_audit_correlation(
        session_id=session_id,
        marker_host=marker,
        agent=agent,
        since=since,
        until=until,
        source=source,
    )
    output = Path(output_path) if output_path else Path("reports") / f"{session_id}.audit-correlation.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = result.to_dict()
    payload["session_sha256"] = sha256_file(path)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result, output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Correlate an Agent Baseline live session with finalized Docker AI Governance audit records"
    )
    parser.add_argument("session")
    parser.add_argument("--path", default=None, help="optional Docker audit directory or finalized .jsonl file")
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)
    try:
        result, output = correlate_session(
            args.session,
            source=args.path,
            output_path=args.output,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    print(f"Correlation evidence: {output}")
    return 0 if result.strength == "exact-marker" else 1


if __name__ == "__main__":
    raise SystemExit(main())
