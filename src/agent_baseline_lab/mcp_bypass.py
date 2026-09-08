from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .commands import exists, parse_json_output, run
from .mcp_policy import analyze_policy


@dataclass(frozen=True)
class MCPBypassResult:
    schema_version: int
    artifact_type: str
    sandbox: str
    server_url: str
    server_host: str
    policy_file: str
    gateway_policy_has_actionless_permit: bool
    gateway_policy_scopes_registration: bool
    gateway_policy_scopes_tools: bool
    network_check_attempted: bool
    network_check_returncode: int | None
    network_decision: str | None
    direct_connection_blocked_by_network_policy: bool | None
    defense_in_depth_verified: bool
    collected_at: str
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _find_decision(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("decision", "result", "effect", "action"):
            item = value.get(key)
            if isinstance(item, str) and item.lower() in {"allow", "allowed", "deny", "denied", "block", "blocked"}:
                return item.lower()
        for item in value.values():
            found = _find_decision(item)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_decision(item)
            if found:
                return found
    return None


def evaluate_direct_mcp_bypass(
    *,
    sandbox: str,
    server_url: str,
    policy_file: str | Path,
    output_path: str | Path,
    dry_run: bool = False,
) -> MCPBypassResult:
    parsed_url = urlparse(server_url)
    host = parsed_url.hostname or ""
    if not host:
        raise ValueError("server_url must contain a hostname")
    analysis = analyze_policy(policy_file)
    network_attempted = False
    network_rc: int | None = None
    network_decision: str | None = None
    blocked: bool | None = None

    if not dry_run:
        if not exists("sbx"):
            raise RuntimeError("Docker Sandboxes CLI (`sbx`) is required for live bypass testing")
        network_attempted = True
        result = run(
            ["sbx", "policy", "check", "network", "--sandbox", sandbox, "--json", server_url],
            timeout=30,
        )
        network_rc = result.returncode
        payload = parse_json_output(result)
        network_decision = _find_decision(payload) if payload is not None else None
        if network_decision is None:
            lowered = (result.stdout + "\n" + result.stderr).lower()
            if "deny" in lowered or "block" in lowered:
                network_decision = "deny"
            elif "allow" in lowered:
                network_decision = "allow"
        if network_decision is not None:
            blocked = network_decision in {"deny", "denied", "block", "blocked"}

    gateway_bounded = (
        not analysis.has_actionless_permit
        and analysis.has_registration_scope
        and analysis.has_tool_scope
    )
    verified = gateway_bounded and blocked is True
    result_payload = MCPBypassResult(
        schema_version=1,
        artifact_type="mcp-direct-bypass-evidence",
        sandbox=sandbox,
        server_url=server_url,
        server_host=host,
        policy_file=str(policy_file),
        gateway_policy_has_actionless_permit=analysis.has_actionless_permit,
        gateway_policy_scopes_registration=analysis.has_registration_scope,
        gateway_policy_scopes_tools=analysis.has_tool_scope,
        network_check_attempted=network_attempted,
        network_check_returncode=network_rc,
        network_decision=network_decision,
        direct_connection_blocked_by_network_policy=blocked,
        defense_in_depth_verified=verified,
        collected_at=_utc_now(),
        claims_boundary=(
            "Docker MCP policy governs only requests handled by the MCP gateway. A direct remote MCP "
            "connection from inside a sandbox is treated as network egress. defense_in_depth_verified "
            "is true only when the reference Cedar policy has bounded registration/tool posture and a "
            "live sandbox network-policy check independently returns deny/block for the direct endpoint."
        ),
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result_payload.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result_payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Test the direct-MCP bypass boundary across MCP and network policy")
    parser.add_argument("--sandbox", required=True)
    parser.add_argument("--server-url", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = evaluate_direct_mcp_bypass(
            sandbox=args.sandbox,
            server_url=args.server_url,
            policy_file=args.policy,
            output_path=args.output,
            dry_run=args.dry_run,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if args.dry_run or result.defense_in_depth_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
