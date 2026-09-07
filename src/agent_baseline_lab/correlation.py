from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

TERMINAL_ALLOW = {"AUDIT_DECISION_ALLOW", "AUDIT_DECISION_APPROVED"}
TERMINAL_BLOCK = {"AUDIT_DECISION_DENY", "AUDIT_DECISION_REJECTED"}
PENDING_APPROVAL = {"AUDIT_DECISION_APPROVAL_REQUIRED"}


@dataclass(frozen=True)
class CorrelatedToolAction:
    evaluation_event_id: str
    execution_event_id: str
    audit_session_id: str
    agent: str
    resource_id: str
    evaluation_decision: str
    evaluation_timestamp: str
    execution_timestamp: str
    latency_ms: int
    basis: list[str]
    confidence: str = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ToolCorrelationReport:
    evaluation_events: int
    execution_events: int
    terminal_allowed: int
    terminal_blocked: int
    approval_required: int
    paired_allowed: int
    unmatched_allowed: list[dict[str, Any]]
    orphan_executions: list[dict[str, Any]]
    pairs: list[CorrelatedToolAction]
    coverage: float | None
    complete: bool
    correlation_model: str
    documented_identifier_gap: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["pairs"] = [pair.to_dict() for pair in self.pairs]
        return payload


def _timestamp(value: object) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _identity_compatible(evaluation: dict[str, Any], execution: dict[str, Any]) -> bool:
    for key in ("audit_session_id", "resource_id"):
        if not evaluation.get(key) or evaluation.get(key) != execution.get(key):
            return False
    eval_agent = str(evaluation.get("agent", "") or "")
    exec_agent = str(execution.get("agent", "") or "")
    return not (eval_agent and exec_agent and eval_agent != exec_agent)


def _event_stub(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "audit_event_id": str(record.get("audit_event_id", "")),
        "timestamp": str(record.get("timestamp", "")),
        "audit_session_id": str(record.get("audit_session_id", "")),
        "agent": str(record.get("agent", "")),
        "resource_id": str(record.get("resource_id", "")),
        "decision": str(record.get("decision", "")),
        "action_type": str(record.get("action_type", "")),
    }


def correlate_tool_events(
    records: list[dict[str, Any]],
    *,
    max_gap_seconds: float = 30.0,
) -> ToolCorrelationReport:
    """Conservatively pair Docker tool-invocation evaluations with execution outcomes.

    Docker documents ``audit_event_id`` as unique per record and
    ``audit_session_id`` as the daemon session identifier. It does not document
    a per-action correlation identifier that directly joins a tool evaluation
    to its execution outcome. This function therefore uses a transparent
    heuristic: same audit session + same resource/tool + compatible agent +
    nearest later execution within ``max_gap_seconds``.
    """

    evaluations = [
        record
        for record in records
        if record.get("category") == "AUDIT_CATEGORY_EVALUATION"
        and record.get("action_type") == "tool_invocation"
    ]
    executions = [
        record
        for record in records
        if record.get("category") == "AUDIT_CATEGORY_EXECUTION"
        and record.get("action_type") == "tool_execution"
    ]
    evaluations.sort(key=lambda record: _timestamp(record.get("timestamp")) or datetime.min.replace(tzinfo=UTC))
    executions.sort(key=lambda record: _timestamp(record.get("timestamp")) or datetime.min.replace(tzinfo=UTC))

    allowed = [record for record in evaluations if record.get("decision") in TERMINAL_ALLOW]
    blocked = [record for record in evaluations if record.get("decision") in TERMINAL_BLOCK]
    pending = [record for record in evaluations if record.get("decision") in PENDING_APPROVAL]

    unused_execution_indexes = set(range(len(executions)))
    pairs: list[CorrelatedToolAction] = []
    unmatched_allowed: list[dict[str, Any]] = []

    for evaluation in allowed:
        evaluation_time = _timestamp(evaluation.get("timestamp"))
        candidates: list[tuple[float, int, dict[str, Any]]] = []
        if evaluation_time is not None:
            for index in sorted(unused_execution_indexes):
                execution = executions[index]
                if not _identity_compatible(evaluation, execution):
                    continue
                execution_time = _timestamp(execution.get("timestamp"))
                if execution_time is None or execution_time < evaluation_time:
                    continue
                delta = (execution_time - evaluation_time).total_seconds()
                if delta <= max_gap_seconds:
                    candidates.append((delta, index, execution))

        if not candidates:
            unmatched_allowed.append(_event_stub(evaluation))
            continue

        delta, index, execution = min(candidates, key=lambda item: item[0])
        unused_execution_indexes.remove(index)
        basis = ["audit_session_id", "resource_id", "temporal_order"]
        if evaluation.get("agent") and execution.get("agent"):
            basis.append("agent")
        pairs.append(
            CorrelatedToolAction(
                evaluation_event_id=str(evaluation.get("audit_event_id", "")),
                execution_event_id=str(execution.get("audit_event_id", "")),
                audit_session_id=str(evaluation.get("audit_session_id", "")),
                agent=str(evaluation.get("agent") or execution.get("agent") or ""),
                resource_id=str(evaluation.get("resource_id", "")),
                evaluation_decision=str(evaluation.get("decision", "")),
                evaluation_timestamp=str(evaluation.get("timestamp", "")),
                execution_timestamp=str(execution.get("timestamp", "")),
                latency_ms=round(delta * 1000),
                basis=basis,
            )
        )

    orphan_executions = [_event_stub(executions[index]) for index in sorted(unused_execution_indexes)]
    coverage = round(len(pairs) / len(allowed), 4) if allowed else None
    complete = bool(allowed) and not unmatched_allowed and not orphan_executions

    return ToolCorrelationReport(
        evaluation_events=len(evaluations),
        execution_events=len(executions),
        terminal_allowed=len(allowed),
        terminal_blocked=len(blocked),
        approval_required=len(pending),
        paired_allowed=len(pairs),
        unmatched_allowed=unmatched_allowed,
        orphan_executions=orphan_executions,
        pairs=pairs,
        coverage=coverage,
        complete=complete,
        correlation_model="same audit_session_id + resource_id + compatible agent + nearest later execution within time window",
        documented_identifier_gap=(
            "Docker documents audit_event_id per event and audit_session_id per daemon session, "
            "but the public audit record reference does not document a per-action correlation ID "
            "joining tool_invocation evaluation to tool_execution outcome."
        ),
    )
