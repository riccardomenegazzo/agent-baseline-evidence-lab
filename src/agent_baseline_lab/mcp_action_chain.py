from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class McpActionChain:
    schema_version: int
    audit_session_id: str
    agent: str
    resource_id: str
    evaluation_event_ids: list[str]
    execution_event_ids: list[str]
    decisions: list[str]
    status: str
    confidence: str
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _timestamp(record: dict[str, Any]) -> str:
    return str(record.get("timestamp", ""))


def _sort_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(record: dict[str, Any]) -> tuple[int, str]:
        raw = _timestamp(record)
        try:
            normalized = raw.replace("Z", "+00:00")
            return (0, datetime.fromisoformat(normalized).isoformat())
        except ValueError:
            return (1, raw)

    return sorted(records, key=key)


def analyze_action_chains(records: list[dict[str, Any]]) -> list[McpActionChain]:
    relevant = [
        record
        for record in records
        if str(record.get("action_type", "")) in {"tool_invocation", "tool_execution"}
    ]
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for record in relevant:
        key = (
            str(record.get("audit_session_id", "")),
            str(record.get("agent", "")),
            str(record.get("resource_id", "")),
        )
        grouped.setdefault(key, []).append(record)

    chains: list[McpActionChain] = []
    for (session_id, agent, resource_id), group in sorted(grouped.items()):
        ordered = _sort_records(group)
        evaluations = [
            record
            for record in ordered
            if record.get("category") == "AUDIT_CATEGORY_EVALUATION"
            or record.get("action_type") == "tool_invocation"
        ]
        executions = [
            record
            for record in ordered
            if record.get("category") == "AUDIT_CATEGORY_EXECUTION"
            or record.get("action_type") == "tool_execution"
        ]
        decisions = [str(record.get("decision", "")) for record in evaluations if record.get("decision")]
        denied = any(decision.endswith(("_DENY", "_REJECTED")) for decision in decisions)
        approval_required = any(decision.endswith("_APPROVAL_REQUIRED") for decision in decisions)
        approved = any(decision.endswith("_APPROVED") for decision in decisions)
        allowed = any(decision.endswith("_ALLOW") for decision in decisions)

        if denied and not executions:
            status = "denied-before-execution"
        elif executions and (allowed or approved):
            status = "complete-observed-chain"
        elif executions and approval_required and not approved:
            status = "execution-without-observed-approval"
        elif evaluations and not executions:
            status = "evaluation-only"
        elif executions:
            status = "execution-without-observed-evaluation"
        else:
            status = "partial"

        distinct_events = {
            str(record.get("audit_event_id", ""))
            for record in ordered
            if record.get("audit_event_id")
        }
        confidence = "bounded"
        if not session_id or not resource_id:
            confidence = "weak"
        elif len(distinct_events) >= 2:
            confidence = "bounded-multi-event"

        chains.append(
            McpActionChain(
                schema_version=1,
                audit_session_id=session_id,
                agent=agent,
                resource_id=resource_id,
                evaluation_event_ids=[
                    str(record.get("audit_event_id", ""))
                    for record in evaluations
                    if record.get("audit_event_id")
                ],
                execution_event_ids=[
                    str(record.get("audit_event_id", ""))
                    for record in executions
                    if record.get("audit_event_id")
                ],
                decisions=decisions,
                status=status,
                confidence=confidence,
                claims_boundary=(
                    "Docker documents audit_event_id as unique per event and audit_session_id as daemon-session scope, "
                    "but no request-level causal identifier is assumed here. Events are grouped conservatively by "
                    "audit_session_id + agent + resource_id; a complete-observed-chain is bounded correlation, not cryptographic causality."
                ),
            )
        )
    return chains


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze Docker MCP evaluation/approval/execution audit chains")
    parser.add_argument("audit_json")
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)
    try:
        payload = json.loads(Path(args.audit_json).read_text(encoding="utf-8"))
        records = payload.get("records", []) if isinstance(payload, dict) else payload
        if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
            raise ValueError("audit input must be a list of records or an object with records")
        chains = analyze_action_chains(records)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    result = {
        "schema_version": 1,
        "chain_count": len(chains),
        "chains": [chain.to_dict() for chain in chains],
    }
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
