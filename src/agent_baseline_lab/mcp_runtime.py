from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .audit import load_audit_records
from .commands import exists, parse_json_output, run

SAFE_AUTH_KEYS = {
    "name",
    "server",
    "status",
    "authorized",
    "authenticated",
    "expiresAt",
    "expires_at",
    "grantedScopes",
    "granted_scopes",
    "defaultScopes",
    "default_scopes",
    "supportedScopes",
    "supported_scopes",
    "requestedScopes",
    "requested_scopes",
}


@dataclass(frozen=True)
class MCPServerObservation:
    name: str
    inspect_attempted: bool
    inspect_returncode: int | None
    inspect_output_sha256: str
    transport: str | None
    server_type: str | None
    identity_url: str | None
    endpoint_url: str | None
    expected_identity_url: str | None
    identity_match: bool | None
    oauth_status_attempted: bool
    oauth_status_returncode: int | None
    oauth_status: Any
    oauth_evidence_contains_secret_material: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MCPRuntimeEvidence:
    schema_version: int
    artifact_type: str
    collected_at: str
    docker_cli_available: bool
    dry_run: bool
    servers: list[MCPServerObservation]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["servers"] = [item.to_dict() for item in self.servers]
        return payload


@dataclass(frozen=True)
class MCPActionChain:
    audit_session_id: str
    resource_id: str
    first_timestamp: str
    last_timestamp: str
    evaluation_seen: bool
    approval_required_seen: bool
    deny_seen: bool
    invocation_seen: bool
    execution_seen: bool
    event_ids: list[str]
    status: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _extract_labeled(text: str, labels: tuple[str, ...]) -> str | None:
    for label in labels:
        pattern = rf"(?im)^\s*{re.escape(label)}\s*[:=]\s*(.+?)\s*$"
        match = re.search(pattern, text)
        if match:
            return match.group(1).strip().strip('"\'')
    return None


def parse_mcp_inspect(text: str) -> dict[str, str | None]:
    identity = _extract_labeled(text, ("identityURL", "identity URL", "identity_url"))
    endpoint = _extract_labeled(text, ("URL", "endpoint", "endpoint URL", "remote URL"))
    transport = _extract_labeled(text, ("transport",))
    server_type = _extract_labeled(text, ("type", "server type"))
    return {
        "identity_url": identity,
        "endpoint_url": endpoint,
        "transport": transport,
        "server_type": server_type,
    }


def _sanitize_auth_payload(value: Any) -> Any:
    if isinstance(value, list):
        return [_sanitize_auth_payload(item) for item in value]
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if key in SAFE_AUTH_KEYS:
                sanitized[key] = _sanitize_auth_payload(item)
            elif isinstance(item, (dict, list)):
                nested = _sanitize_auth_payload(item)
                if nested not in ({}, []):
                    sanitized[key] = nested
        return sanitized
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _contains_secret_key_names(value: Any) -> bool:
    secret_markers = {"token", "secret", "password", "authorization", "credential", "refresh"}
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = key.lower()
            if any(marker in lowered for marker in secret_markers):
                return True
            if _contains_secret_key_names(item):
                return True
    elif isinstance(value, list):
        return any(_contains_secret_key_names(item) for item in value)
    return False


def _auth_status(name: str) -> tuple[bool, int | None, Any]:
    primary = run(["sbx", "mcp", "auth", "status", name, "--format=json"], timeout=30)
    parsed = parse_json_output(primary)
    if primary.ok and parsed is not None:
        sanitized = _sanitize_auth_payload(parsed)
        return True, primary.returncode, sanitized
    fallback = run(["sbx", "mcp", "auth", "status", name, "--json"], timeout=30)
    parsed = parse_json_output(fallback)
    if fallback.ok and parsed is not None:
        sanitized = _sanitize_auth_payload(parsed)
        return True, fallback.returncode, sanitized
    return True, fallback.returncode, {}


def collect_mcp_runtime_evidence(
    server_names: list[str],
    *,
    expected_identity_urls: dict[str, str] | None = None,
    output_path: str | Path,
    dry_run: bool = False,
) -> MCPRuntimeEvidence:
    expected_identity_urls = expected_identity_urls or {}
    cli_available = exists("sbx")
    if not dry_run and not cli_available:
        raise RuntimeError("Docker Sandboxes CLI (`sbx`) is required for live MCP collection")
    observations: list[MCPServerObservation] = []
    for name in server_names:
        expected = expected_identity_urls.get(name)
        if dry_run:
            observations.append(
                MCPServerObservation(
                    name=name,
                    inspect_attempted=False,
                    inspect_returncode=None,
                    inspect_output_sha256=_sha256_text(""),
                    transport=None,
                    server_type=None,
                    identity_url=None,
                    endpoint_url=None,
                    expected_identity_url=expected,
                    identity_match=None,
                    oauth_status_attempted=False,
                    oauth_status_returncode=None,
                    oauth_status={},
                    oauth_evidence_contains_secret_material=False,
                )
            )
            continue

        inspect = run(["sbx", "mcp", "inspect", name], timeout=30)
        parsed = parse_mcp_inspect(inspect.stdout if inspect.ok else "")
        identity = parsed["identity_url"]
        identity_match = (identity == expected) if expected and identity else None
        auth_attempted, auth_rc, auth_payload = _auth_status(name)
        observations.append(
            MCPServerObservation(
                name=name,
                inspect_attempted=True,
                inspect_returncode=inspect.returncode,
                inspect_output_sha256=_sha256_text(inspect.stdout + "\n" + inspect.stderr),
                transport=parsed["transport"],
                server_type=parsed["server_type"],
                identity_url=identity,
                endpoint_url=parsed["endpoint_url"],
                expected_identity_url=expected,
                identity_match=identity_match,
                oauth_status_attempted=auth_attempted,
                oauth_status_returncode=auth_rc,
                oauth_status=auth_payload,
                oauth_evidence_contains_secret_material=_contains_secret_key_names(auth_payload),
            )
        )

    evidence = MCPRuntimeEvidence(
        schema_version=1,
        artifact_type="mcp-runtime-evidence",
        collected_at=_utc_now(),
        docker_cli_available=cli_available,
        dry_run=dry_run,
        servers=observations,
        claims_boundary=(
            "Identity matching is claimed only when `sbx mcp inspect` exposes a labeled identity URL. "
            "OAuth evidence stores only whitelisted status/scope metadata and never token, secret, "
            "password, refresh-token, or authorization values."
        ),
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def correlate_mcp_action_chains(records: list[dict[str, Any]]) -> list[MCPActionChain]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records:
        action = str(record.get("action_type", "")).lower()
        category = str(record.get("category", ""))
        if action not in {"tool_invocation", "tool_execution"} and category != "AUDIT_CATEGORY_EVALUATION":
            continue
        session = str(record.get("audit_session_id", ""))
        resource = str(record.get("resource_id", ""))
        if not session or not resource:
            continue
        grouped.setdefault((session, resource), []).append(record)

    chains: list[MCPActionChain] = []
    for (session, resource), group in sorted(grouped.items()):
        ordered = sorted(group, key=lambda item: str(item.get("timestamp", "")))
        categories = {str(item.get("category", "")) for item in ordered}
        decisions = {str(item.get("decision", "")) for item in ordered}
        actions = {str(item.get("action_type", "")).lower() for item in ordered}
        deny = any(value.endswith(("_DENY", "_REJECTED")) for value in decisions)
        approval = any(value.endswith("_APPROVAL_REQUIRED") for value in decisions)
        execution = "tool_execution" in actions
        invocation = "tool_invocation" in actions
        evaluation = "AUDIT_CATEGORY_EVALUATION" in categories
        if deny and not execution:
            status = "denied-no-execution"
        elif evaluation and execution:
            status = "evaluated-executed"
        elif invocation and execution:
            status = "invoked-executed"
        elif evaluation:
            status = "evaluated-no-execution-observed"
        else:
            status = "partial"
        chains.append(
            MCPActionChain(
                audit_session_id=session,
                resource_id=resource,
                first_timestamp=str(ordered[0].get("timestamp", "")),
                last_timestamp=str(ordered[-1].get("timestamp", "")),
                evaluation_seen=evaluation,
                approval_required_seen=approval,
                deny_seen=deny,
                invocation_seen=invocation,
                execution_seen=execution,
                event_ids=sorted(
                    {str(item.get("audit_event_id")) for item in ordered if item.get("audit_event_id")}
                ),
                status=status,
            )
        )
    return chains


def correlate_audit_file(
    *,
    source: str | Path | None,
    output_path: str | Path,
    audit_session_id: str | None = None,
    agent: str | None = None,
) -> list[MCPActionChain]:
    records, summary = load_audit_records(
        source,
        audit_session_id=audit_session_id,
        agent=agent,
    )
    chains = correlate_mcp_action_chains(records)
    payload = {
        "schema_version": 1,
        "artifact_type": "mcp-action-chain-evidence",
        "source_summary": summary.to_dict(),
        "chains": [item.to_dict() for item in chains],
        "claims_boundary": (
            "Chains correlate only records sharing Docker audit_session_id and resource_id. They do "
            "not prove association with a specific coding task unless a separate exact run marker or "
            "equivalent cross-system identifier is verified."
        ),
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return chains


def _parse_expect(values: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--expect values must use name=https://identity.example form")
        name, url = value.split("=", 1)
        out[name.strip()] = url.strip()
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect secret-free Docker MCP runtime evidence")
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect")
    collect.add_argument("servers", nargs="+")
    collect.add_argument("--expect", action="append", default=[])
    collect.add_argument("--output", required=True)
    collect.add_argument("--dry-run", action="store_true")

    chains = sub.add_parser("chains")
    chains.add_argument("--path", default=None)
    chains.add_argument("--audit-session-id", default=None)
    chains.add_argument("--agent", default=None)
    chains.add_argument("--output", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            evidence = collect_mcp_runtime_evidence(
                args.servers,
                expected_identity_urls=_parse_expect(args.expect),
                output_path=args.output,
                dry_run=args.dry_run,
            )
            print(json.dumps(evidence.to_dict(), indent=2, sort_keys=True))
            return 0
        result = correlate_audit_file(
            source=args.path,
            output_path=args.output,
            audit_session_id=args.audit_session_id,
            agent=args.agent,
        )
        print(json.dumps([item.to_dict() for item in result], indent=2, sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
