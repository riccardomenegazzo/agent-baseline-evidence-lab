from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .privacy import sanitize_text, sanitize_value

GENESIS_HASH = "0" * 64


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _event_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


class TraceLedger:
    """Append-only, hash-chained NDJSON ledger for one assessment run.

    When privacy_root is supplied, project/home path prefixes are minimized before
    an event is hashed and persisted. This preserves a single canonical evidence
    representation instead of redacting an already-hashed trace later.
    """

    def __init__(self, path: Path, run_id: str, *, privacy_root: Path | None = None):
        self.path = path
        self.run_id = run_id
        self.privacy_root = privacy_root.resolve() if privacy_root is not None else None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.sequence = 0
        self.previous_hash = GENESIS_HASH
        if self.path.exists():
            self.path.unlink()

    def _text(self, value: str) -> str:
        if self.privacy_root is None:
            return value
        return sanitize_text(value, self.privacy_root)

    def _value(self, value: Any) -> Any:
        if self.privacy_root is None:
            return value
        return sanitize_value(value, self.privacy_root)

    def append(
        self,
        event_type: str,
        *,
        actor: str,
        action: str,
        target: str = "",
        decision: str = "",
        result: str = "",
        task_id: str = "",
        control_id: str = "",
        attributes: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.sequence += 1
        unsigned: dict[str, Any] = {
            "sequence": self.sequence,
            "timestamp": _utc_now(),
            "run_id": self._text(self.run_id),
            "event_type": self._text(event_type),
            "actor": self._text(actor),
            "action": self._text(action),
            "target": self._text(target),
            "decision": self._text(decision),
            "result": self._text(result),
            "task_id": self._text(task_id),
            "control_id": self._text(control_id),
            "attributes": self._value(attributes or {}),
            "prev_event_hash": self.previous_hash,
        }
        digest = _event_hash(unsigned)
        record = {**unsigned, "event_hash": digest}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
        self.previous_hash = digest
        return record

    @property
    def head_hash(self) -> str:
        return self.previous_hash


def read_trace(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def verify_trace(path: Path) -> tuple[bool, list[str]]:
    if not path.exists():
        return False, [f"trace ledger is missing: {path}"]

    errors: list[str] = []
    expected_prev = GENESIS_HASH
    expected_sequence = 1
    for line_no, event in enumerate(read_trace(path), start=1):
        observed_sequence = event.get("sequence")
        if observed_sequence != expected_sequence:
            errors.append(
                f"line {line_no}: sequence mismatch: expected {expected_sequence}, got {observed_sequence}"
            )
        observed_prev = event.get("prev_event_hash")
        if observed_prev != expected_prev:
            errors.append(f"line {line_no}: prev_event_hash mismatch")

        observed_hash = event.get("event_hash")
        unsigned = dict(event)
        unsigned.pop("event_hash", None)
        calculated = _event_hash(unsigned)
        if observed_hash != calculated:
            errors.append(f"line {line_no}: event_hash mismatch")

        expected_prev = str(observed_hash or "")
        expected_sequence += 1

    if expected_sequence == 1:
        errors.append("trace ledger is empty")
    return not errors, errors
