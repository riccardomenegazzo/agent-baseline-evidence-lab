from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .commands import exists, run
from .config import get_path
from .evidence import EvidenceStore
from .mcp_policy import analyze_policy


def _trace(ctx: dict[str, Any], event_type: str, *, scenario_id: str, action: str, target: str = "", decision: str = "", result: str = "", attributes: dict[str, Any] | None = None) -> None:
    ledger = ctx.get("trace")
    if ledger is None:
        return
    ledger.append(
        event_type,
        actor="agent-baseline-evidence-lab",
        action=action,
        target=target,
        decision=decision,
        result=result,
        task_id=str(ctx.get("task_id", "")),
        control_id="VAL-01",
        attributes={"scenario_id": scenario_id, **(attributes or {})},
    )


def _network_policy_scenario(scenario: dict[str, Any], cfg: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    sid = str(scenario.get("id", "network-policy"))
    sandbox = str(get_path(cfg, "sandbox.name", ""))
    target = str(scenario.get("target", ""))
    expected = str(scenario.get("expected_decision", scenario.get("expected", "deny"))).lower()
    if expected not in {"allow", "deny"}:
        return {"id": sid, "type": "network-policy", "status": "ERROR", "reason": f"unsupported expected decision: {expected}"}
    if not exists("sbx"):
        return {"id": sid, "type": "network-policy", "status": "SKIP", "reason": "sbx is not installed", "target": target, "expected": expected}
    if not sandbox or not target:
        return {"id": sid, "type": "network-policy", "status": "ERROR", "reason": "sandbox.name and scenario.target are required"}
    cmd = ["sbx", "policy", "check", "network", "--sandbox", sandbox, target]
    result = run(cmd)
    observed = (result.stdout or result.stderr).strip()
    matched = result.ok and ((expected == "deny" and "denied:" in observed.lower()) or (expected == "allow" and "allowed:" in observed.lower()))
    _trace(ctx, "scenario.network-policy", scenario_id=sid, action="policy-check", target=target, decision=expected, result="pass" if matched else "fail", attributes={"sandbox": sandbox, "observed": observed})
    return {
        "id": sid,
        "type": "network-policy",
        "status": "PASS" if matched else "FAIL",
        "target": target,
        "sandbox": sandbox,
        "expected": expected,
        "observed": observed,
        "command": cmd,
        "returncode": result.returncode,
    }


def _host_canary_scenario(scenario: dict[str, Any], cfg: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    sid = str(scenario.get("id", "host-filesystem-separation"))
    sandbox = str(get_path(cfg, "sandbox.name", ""))
    if not exists("sbx"):
        return {"id": sid, "type": "host-canary", "status": "SKIP", "reason": "sbx is not installed"}
    if not sandbox:
        return {"id": sid, "type": "host-canary", "status": "ERROR", "reason": "sandbox.name is required"}

    canary = Path(f"/tmp/abl-scenario-canary-{ctx['run_id']}")
    try:
        canary.write_text("host-only\n", encoding="utf-8")
        probe = run(["sbx", "exec", sandbox, "sh", "-lc", f"test ! -e {canary}"])
    finally:
        try:
            os.unlink(canary)
        except FileNotFoundError:
            pass
    matched = probe.ok
    _trace(ctx, "scenario.host-canary", scenario_id=sid, action="host-path-visibility", target=str(canary), decision="deny", result="pass" if matched else "fail", attributes={"sandbox": sandbox, "returncode": probe.returncode})
    return {
        "id": sid,
        "type": "host-canary",
        "status": "PASS" if matched else "FAIL",
        "sandbox": sandbox,
        "target": str(canary),
        "expected": "host path absent inside sandbox",
        "observed": "absent" if matched else "visible-or-probe-error",
        "returncode": probe.returncode,
        "stdout": probe.stdout,
        "stderr": probe.stderr,
    }


def _mcp_policy_contract_scenario(scenario: dict[str, Any], cfg: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    sid = str(scenario.get("id", "mcp-policy-contract"))
    raw_path = scenario.get("policy_file")
    if not raw_path:
        files = get_path(cfg, "assessment.mcp_policy_files", [])
        raw_path = files[0] if files else ""
    path = Path(str(raw_path))
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.exists():
        return {"id": sid, "type": "mcp-policy-contract", "status": "ERROR", "reason": f"policy file not found: {raw_path}"}
    analysis = analyze_policy(path).to_dict()
    requirements = scenario.get(
        "require",
        ["no_actionless_permit", "registration_identity_binding", "tool_scope", "approval_guard", "local_stdio_forbid"],
    )
    checks = {
        "no_actionless_permit": not bool(analysis["has_actionless_permit"]),
        "registration_identity_binding": bool(analysis["has_registration_scope"] and analysis["has_identity_url_binding"]),
        "tool_scope": bool(analysis["has_tool_scope"]),
        "approval_guard": bool(analysis["has_approval_guard"]),
        "local_stdio_forbid": bool(analysis["has_local_stdio_forbid"]),
        "primordial_scope": bool(analysis.get("has_primordial_scope", False)),
    }
    unknown = [name for name in requirements if name not in checks]
    failed = [name for name in requirements if name in checks and not checks[name]]
    status = "ERROR" if unknown else ("PASS" if not failed else "FAIL")
    _trace(ctx, "scenario.mcp-policy-contract", scenario_id=sid, action="static-policy-contract", target=str(path), decision="allowlist", result=status.lower(), attributes={"failed": failed, "unknown": unknown})
    return {
        "id": sid,
        "type": "mcp-policy-contract",
        "status": status,
        "policy_file": str(path),
        "required_contracts": requirements,
        "checks": checks,
        "failed": failed,
        "unknown": unknown,
        "analysis": analysis,
    }


def run_scenarios(cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> tuple[list[dict[str, Any]], object]:
    declared = get_path(cfg, "assessment.adversarial_scenarios", [])
    results: list[dict[str, Any]] = []
    for scenario in declared if isinstance(declared, list) else []:
        if not isinstance(scenario, dict) or scenario.get("enabled", True) is False:
            continue
        scenario_type = str(scenario.get("type", ""))
        if scenario_type == "network-policy":
            result = _network_policy_scenario(scenario, cfg, ctx)
        elif scenario_type == "host-canary":
            result = _host_canary_scenario(scenario, cfg, ctx)
        elif scenario_type == "mcp-policy-contract":
            result = _mcp_policy_contract_scenario(scenario, cfg, ctx)
        else:
            result = {
                "id": str(scenario.get("id", "unnamed")),
                "type": scenario_type or "unspecified",
                "status": "ERROR",
                "reason": f"unsupported scenario type: {scenario_type or '<missing>'}",
            }
        results.append(result)

    evidence = store.write_json(
        "controls/VAL-01/scenario-results.json",
        {"scenarios": results},
        "Executed adversarial scenario results. SKIP means the required live surface was unavailable; it is never treated as PASS.",
    )
    return results, evidence
