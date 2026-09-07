from __future__ import annotations

import hashlib
import json
import os
import platform
from collections import deque
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SENSITIVE_FIELDS = {"username", "user_email", "org_id", "org_name", "hostname"}


@dataclass(frozen=True)
class AuditIngestSummary:
    source_path: str
    files_scanned: int
    records_seen: int
    records_selected: int
    audit_session_ids: list[str]
    categories: dict[str, int]
    decisions: dict[str, int]
    action_types: dict[str, int]
    agents: list[str]
    schema_versions: list[str]
    parse_errors: int
    redaction: str = "run-scoped SHA-256 pseudonymization"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def default_audit_dir() -> Path:
    system = platform.system().lower()
    home = Path.home()
    if system == "darwin":
        return home / "Library" / "Logs" / "com.docker.sandboxes" / "sandboxes" / "auditkit"
    if system == "windows":
        local = os.environ.get("LOCALAPPDATA")
        base = Path(local) if local else home / "AppData" / "Local"
        return base / "DockerSandboxes" / "sandboxes" / "logs" / "auditkit"
    state_home = Path(os.environ.get("XDG_STATE_HOME", home / ".local" / "state"))
    return state_home / "sandboxes" / "sandboxes" / "auditkit"


def _pseudonym(value: object, salt: str) -> str:
    raw = f"{salt}\0{value}".encode("utf-8", errors="replace")
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:16]


def redact_record(record: dict[str, Any], salt: str) -> dict[str, Any]:
    """Redact identity/host fields while preserving within-run correlation."""
    redacted: dict[str, Any] = {}
    for key, value in record.items():
        if key in SENSITIVE_FIELDS and value not in (None, ""):
            redacted[key] = _pseudonym(value, salt)
        else:
            redacted[key] = value
    return redacted


def _iter_jsonl_files(root: Path) -> Iterable[Path]:
    if root.is_file() and root.suffix == ".jsonl":
        yield root
        return
    if not root.exists() or not root.is_dir():
        return
    # .tmp files are intentionally ignored: Docker documents them as incomplete.
    files = [p for p in root.rglob("*.jsonl") if p.is_file()]
    yield from sorted(files, key=lambda p: (p.stat().st_mtime, str(p)))


def _parse_timestamp(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def load_audit_records(
    source: str | Path | None = None,
    *,
    audit_session_id: str | None = None,
    agent: str | None = None,
    since: str | None = None,
    until: str | None = None,
    max_records: int = 2000,
    redaction_salt: str = "agent-baseline-evidence-lab",
) -> tuple[list[dict[str, Any]], AuditIngestSummary]:
    root = Path(source).expanduser() if source else default_audit_dir()
    files = list(_iter_jsonl_files(root))
    selected_queue: deque[dict[str, Any]] = deque(maxlen=max(1, max_records))
    records_seen = 0
    parse_errors = 0

    for file_path in files:
        try:
            with file_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    records_seen += 1
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        parse_errors += 1
                        continue
                    if not isinstance(record, dict):
                        parse_errors += 1
                        continue
                    if audit_session_id and str(record.get("audit_session_id", "")) != audit_session_id:
                        continue
                    if agent and str(record.get("agent", "")) != agent:
                        continue
                    timestamp = str(record.get("timestamp", ""))
                    if (since or until) and timestamp:
                        try:
                            observed_time = _parse_timestamp(timestamp)
                            since_time = _parse_timestamp(since) if since else None
                            until_time = _parse_timestamp(until) if until else None
                        except ValueError:
                            parse_errors += 1
                            continue
                        if since_time and observed_time < since_time:
                            continue
                        if until_time and observed_time > until_time:
                            continue
                    selected_queue.append(redact_record(record, redaction_salt))
        except (OSError, UnicodeError):
            parse_errors += 1
            continue

    selected = list(selected_queue)

    def counts(field: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for record in selected:
            value = str(record.get(field, "") or "")
            if value:
                out[value] = out.get(value, 0) + 1
        return dict(sorted(out.items()))

    summary = AuditIngestSummary(
        source_path=str(root),
        files_scanned=len(files),
        records_seen=records_seen,
        records_selected=len(selected),
        audit_session_ids=sorted({str(r.get("audit_session_id")) for r in selected if r.get("audit_session_id")}),
        categories=counts("category"),
        decisions=counts("decision"),
        action_types=counts("action_type"),
        agents=sorted({str(r.get("agent")) for r in selected if r.get("agent")}),
        schema_versions=sorted({str(r.get("schema_version")) for r in selected if r.get("schema_version")}),
        parse_errors=parse_errors,
    )
    return selected, summary


def normalized_result(record: dict[str, Any]) -> str:
    category = str(record.get("category", ""))
    decision = str(record.get("decision", ""))
    if decision.endswith(("_DENY", "_REJECTED")):
        return "denied"
    if decision.endswith(("_ALLOW", "_APPROVED")):
        return "allowed"
    if decision.endswith("_APPROVAL_REQUIRED"):
        return "approval-required"
    if category == "AUDIT_CATEGORY_EXECUTION":
        return "executed"
    return "observed"
