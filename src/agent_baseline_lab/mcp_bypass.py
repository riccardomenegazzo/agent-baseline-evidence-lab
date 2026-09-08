from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .commands import exists, parse_json_output, run


@dataclass(frozen=True)
class McpBypassProbeResult:
    schema_version: int
    sandbox: str
    remote_host: str
    policy_observed: bool
    direct_connection_decision: str
    bypass_blocked: bool
    command_returncode: int | None
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _decision_from_payload(payload: Any) -> str:
    if isinstance(payload, dict):
        for key in ("decision", "result", "effect", "action"):
            value = payload.get(key)
            if isinstance(value, str):
                lowered = value.lower()
                if "deny" in lowered or "block" in lowered:
                    return "deny"
                if "allow" in lowered or "permit" in lowered:
                    return "allow"
        for value in payload.values():
            decision = _decision_from_payload(value)
            if decision != "unknown":
                return decision
    elif isinstance(payload, list):
        for value in payload:
            decision = _decision_from_payload(value)
            if decision != "unknown":
                return decision
    return "unknown"


def probe_direct_mcp_bypass(sandbox: str, remote_host: str, *, dry_run: bool = False) -> McpBypassProbeResult:
    if not sandbox.strip() or not remote_host.strip():
        raise ValueError("sandbox and remote_host are required")
    if dry_run or not exists("sbx"):
        return McpBypassProbeResult(
            schema_version=1,
            sandbox=sandbox,
            remote_host=remote_host,
            policy_observed=False,
            direct_connection_decision="unknown",
            bypass_blocked=False,
            command_returncode=None,
            claims_boundary=(
                "No live Docker network-policy decision was observed. A dry run or missing sbx CLI cannot prove direct MCP bypass prevention."
            ),
        )

    result = run(["sbx", "policy", "check", "network", sandbox, remote_host], timeout=30)
    parsed = parse_json_output(result)
    decision = _decision_from_payload(parsed)
    if decision == "unknown":
        combined = f"{result.stdout}\n{result.stderr}".lower()
        if "deny" in combined or "block" in combined:
            decision = "deny"
        elif "allow" in combined or "permit" in combined:
            decision = "allow"

    return McpBypassProbeResult(
        schema_version=1,
        sandbox=sandbox,
        remote_host=remote_host,
        policy_observed=result.ok or decision != "unknown",
        direct_connection_decision=decision,
        bypass_blocked=decision == "deny",
        command_returncode=result.returncode,
        claims_boundary=(
            "This proves the Docker network-policy decision for direct sandbox egress to the remote MCP host. "
            "It does not prove the host-side MCP gateway itself is unavailable; the gateway is intentionally a separate path."
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Test whether direct sandbox access can bypass the host-side MCP gateway")
    parser.add_argument("--sandbox", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)
    try:
        result = probe_direct_mcp_bypass(args.sandbox, args.host, dry_run=args.dry_run)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    payload = result.to_dict()
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    if args.dry_run:
        return 0
    return 0 if result.bypass_blocked else 1


if __name__ == "__main__":
    raise SystemExit(main())
