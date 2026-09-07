from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from .commands import exists, parse_json_output, run
from .config import get_path, missing_paths
from .evidence import EvidenceStore
from .mcp_policy import analyze_policy
from .models import Result, Status
from .scenarios import run_scenarios
from .trace import read_trace, verify_trace

Evaluator = Callable[[str, dict[str, Any], EvidenceStore, dict[str, Any]], Result]


def _trace(ctx: dict[str, Any], event_type: str, *, control_id: str, action: str, target: str = "", decision: str = "", result: str = "", attributes: dict[str, Any] | None = None) -> None:
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
        control_id=control_id,
        attributes=attributes or {},
    )


def _manifest(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    requirements = {
        "DIS-01": ["agent.id"],
        "DIS-02": ["agent.purpose", "agent.owners.business", "agent.owners.technical", "agent.risk.classification"],
        "DIS-03": ["agent.status.current", "agent.status.decision_history"],
        "DIS-05": ["agent.components"],
        "DIS-06": ["agent.access.identities", "agent.access.resources", "agent.access.actions"],
    }
    missing = missing_paths(cfg, requirements[control_id])
    evidence = store.write_json(
        f"controls/{control_id}/declared-state.json",
        {"checked_fields": requirements[control_id], "missing_fields": missing},
        "Declared agent metadata used for this assessment.",
    )
    _trace(ctx, "inventory.validation", control_id=control_id, action="validate-declared-state", target=str(get_path(cfg, "agent.id", "")), result="fail" if missing else "pass")
    if missing:
        return Result(control_id, Status.FAIL, "Required declared state is incomplete.", missing, [evidence], "manifest")
    if control_id == "DIS-05":
        return Result(
            control_id,
            Status.PARTIAL,
            "Declared component composition is mapped, but runtime-resolved versions, downstream agents and impact lookup are not fully observed.",
            ["A declared component list alone is not promoted to full composition evidence."],
            [evidence],
            "manifest",
        )
    if control_id == "DIS-06":
        return Result(
            control_id,
            Status.PARTIAL,
            "Declared identities, resources and actions are mapped; effective runtime permissions and material-run delegation still require observed authority evidence.",
            ["Declared access is not assumed to equal effective access."],
            [evidence],
            "manifest",
        )
    return Result(control_id, Status.PASS, "Required declared state is present.", evidence=[evidence], evaluator="manifest")


def _component_registry(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    components = get_path(cfg, "agent.components", [])
    required = {"id", "type", "source", "version", "owner"}
    problems = []
    if not isinstance(components, list) or not components:
        problems.append("agent.components is empty")
    else:
        for idx, component in enumerate(components):
            missing = sorted(required - set(component)) if isinstance(component, dict) else sorted(required)
            if missing:
                problems.append(f"component[{idx}] missing: {', '.join(missing)}")

    observed_mcp = None
    if exists("sbx"):
        mcp = run(["sbx", "mcp", "ls"])
        observed_mcp = {"returncode": mcp.returncode, "stdout": mcp.stdout, "stderr": mcp.stderr}
    evidence = store.write_json(
        f"controls/{control_id}/component-inventory.json",
        {"declared_components": components, "validation_errors": problems, "observed_mcp_registrations": observed_mcp},
        "Declared component registry plus Docker MCP registration observation when available.",
    )
    _trace(ctx, "component.inventory", control_id=control_id, action="inventory-components", target="agent-components", result="fail" if problems else "pass", attributes={"count": len(components) if isinstance(components, list) else 0})
    status = Status.PASS if not problems else Status.FAIL
    summary = "Component inventory is structurally complete."
    if not problems and observed_mcp is None:
        summary += " Live MCP registrations were not observed because sbx is unavailable."
    return Result(control_id, status, summary if not problems else "Component inventory is incomplete.", problems, [evidence], "component-registry")


def _discovery_reconciliation(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    sources = get_path(cfg, "assessment.discovery_sources", [])
    evidence = store.write_json(
        f"controls/{control_id}/reconciliation-sources.json",
        {"declared_sources": sources},
        "Configured sources that could reconcile declared and observed agent state.",
    )
    _trace(ctx, "discovery.reconciliation", control_id=control_id, action="reconcile-sources", target="inventory", result="partial" if len(sources) >= 2 else "manual", attributes={"source_count": len(sources)})
    if len(sources) >= 2:
        return Result(control_id, Status.PARTIAL, "Reconciliation sources are declared, but continuous discovery is not proven by this lab.", ["At least one real inventory/runtime connector is required for full evidence."], [evidence], "reconciliation")
    return Result(control_id, Status.MANUAL, "Automated cross-system discovery is not configured.", ["Configure assessment.discovery_sources and provide observed inventory evidence."], [evidence], "reconciliation")


def _admission(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    state = {
        "registered": bool(get_path(cfg, "agent.id")),
        "risk_classified": bool(get_path(cfg, "agent.risk.classification")),
        "approved": get_path(cfg, "agent.status.current") == "approved",
        "validation_evidence": bool(get_path(cfg, "agent.status.validation_evidence")),
        "runtime_profile": bool(get_path(cfg, "sandbox.name")),
    }
    evidence = store.write_json(f"controls/{control_id}/admission-inputs.json", state, "Declared admission inputs.")
    _trace(ctx, "admission.assessment", control_id=control_id, action="evaluate-admission-prerequisites", target=str(get_path(cfg, "agent.id", "")), decision="allow" if all(state.values()) else "deny", result="partial" if all(state.values()) else "fail")
    if not all(state.values()):
        return Result(control_id, Status.FAIL, "One or more admission prerequisites are missing.", [k for k, v in state.items() if not v], [evidence], "admission")
    return Result(control_id, Status.PARTIAL, "Admission prerequisites are present; blocking deployment is not yet enforced by this lab.", ["A CI/runtime admission gate is required to prove enforcement."], [evidence], "admission")


def _toxic_combo(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    caps = get_path(cfg, "agent.capabilities", [])
    kinds = {c.get("kind") for c in caps if isinstance(c, dict)}
    lethal = {"untrusted_input", "sensitive_data", "external_write"}
    present = sorted(lethal & kinds)
    evidence = store.write_json(
        f"controls/{control_id}/capability-graph.json",
        {"declared_capabilities": caps, "lethal_trifecta_dimensions_present": present},
        "Minimal toxic-capability graph used by the detector.",
    )
    if lethal.issubset(kinds):
        _trace(ctx, "capability.risk", control_id=control_id, action="detect-toxic-combination", target="capability-graph", decision="deny", result="fail", attributes={"combination": sorted(lethal)})
        return Result(control_id, Status.FAIL, "A high-risk toxic capability combination is declared.", ["untrusted_input + sensitive_data + external_write"], [evidence], "toxic-capability-detector")
    _trace(ctx, "capability.risk", control_id=control_id, action="detect-toxic-combination", target="capability-graph", result="partial" if caps else "manual", attributes={"present_dimensions": present})
    if caps:
        return Result(control_id, Status.PARTIAL, "No known three-way toxic combination was found by the current detector.", ["The draft also calls for emergent-combination modelling; graph reachability is a future extension."], [evidence], "toxic-capability-detector")
    return Result(control_id, Status.MANUAL, "No capability graph is declared.", ["Declare agent.capabilities to run toxic-combination detection."], [evidence], "toxic-capability-detector")


def _sbx_isolation(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    sandbox = get_path(cfg, "sandbox.name")
    if not sandbox:
        return Result(control_id, Status.FAIL, "sandbox.name is required for the Docker Sandboxes live probe.", evaluator="docker-sbx")
    if not exists("sbx"):
        _trace(ctx, "sandbox.probe", control_id=control_id, action="probe-isolation", target=str(sandbox), result="manual", attributes={"reason": "sbx-not-installed"})
        return Result(control_id, Status.MANUAL, "Docker Sandboxes CLI is not installed on this host.", ["Install sbx and rerun to collect live isolation evidence."], evaluator="docker-sbx")

    version = run(["sbx", "version"])
    listing = run(["sbx", "ls", "--json"])
    policies = run(["sbx", "policy", "ls", sandbox, "--json"])
    network_policies = run(["sbx", "policy", "ls", sandbox, "--type", "network", "--json"])
    filesystem_policies = run(["sbx", "policy", "ls", sandbox, "--type", "filesystem", "--json"])
    policy_log = run(["sbx", "policy", "log", sandbox, "--json", "--limit", "50"])
    ev = [
        store.write_text(f"controls/{control_id}/sbx-version.txt", version.stdout + "\n" + version.stderr, "Docker Sandboxes CLI version."),
        store.write_text(f"controls/{control_id}/sbx-ls.json", listing.stdout or listing.stderr, "Live sandbox inventory."),
        store.write_text(f"controls/{control_id}/sbx-policy.json", policies.stdout or policies.stderr, "Active policy response for the target sandbox."),
        store.write_text(f"controls/{control_id}/sbx-policy-network.json", network_policies.stdout or network_policies.stderr, "Active network policy response for the target sandbox."),
        store.write_text(f"controls/{control_id}/sbx-policy-filesystem.json", filesystem_policies.stdout or filesystem_policies.stderr, "Active filesystem policy response for the target sandbox."),
        store.write_text(f"controls/{control_id}/sbx-policy-log.json", policy_log.stdout or policy_log.stderr, "Recent Docker Sandbox policy log entries for the target sandbox."),
    ]
    if not listing.ok:
        _trace(ctx, "sandbox.inventory", control_id=control_id, action="list-sandboxes", target=str(sandbox), result="fail")
        return Result(control_id, Status.FAIL, "Could not enumerate Docker Sandboxes.", [listing.stderr], ev, "docker-sbx")

    listing_json = parse_json_output(listing)
    serialized = json.dumps(listing_json) if listing_json is not None else listing.stdout
    if sandbox not in serialized:
        _trace(ctx, "sandbox.inventory", control_id=control_id, action="locate-sandbox", target=str(sandbox), result="fail")
        return Result(control_id, Status.FAIL, f"Target sandbox '{sandbox}' is not present.", ["Create it with `make sandbox-create`."], ev, "docker-sbx")

    canary_path = f"/tmp/abl-host-canary-{ctx['run_id']}"
    try:
        Path(canary_path).write_text("host-only\n", encoding="utf-8")
        host_probe = run(["sbx", "exec", sandbox, "sh", "-lc", f"test ! -e {canary_path}"])
    finally:
        try:
            os.unlink(canary_path)
        except FileNotFoundError:
            pass
    ev.append(store.write_json(
        f"controls/{control_id}/host-canary-probe.json",
        {"path": canary_path, "returncode": host_probe.returncode, "stdout": host_probe.stdout, "stderr": host_probe.stderr},
        "Safe host-filesystem separation canary probe.",
    ))
    _trace(ctx, "sandbox.filesystem", control_id=control_id, action="host-canary-visibility", target=canary_path, decision="deny" if host_probe.ok else "unexpected", result="pass" if host_probe.ok else "fail")

    required_denies = get_path(cfg, "sandbox.network.required_denies", [])
    required_allows = get_path(cfg, "sandbox.network.required_allows", [])
    policy_checks = []
    failures = []
    for target, expected in [(x, "Denied") for x in required_denies] + [(x, "Allowed") for x in required_allows]:
        check = run(["sbx", "policy", "check", "network", "--sandbox", sandbox, target])
        observed = check.stdout or check.stderr
        ok = check.ok and expected.lower() in observed.lower()
        policy_checks.append({"target": target, "expected": expected, "observed": observed, "ok": ok})
        _trace(ctx, "policy.decision", control_id=control_id, action="network-access", target=target, decision=expected.lower(), result="pass" if ok else "fail", attributes={"observed": observed})
        if not ok:
            failures.append(f"network policy mismatch for {target}: expected {expected}")
    ev.append(store.write_json(f"controls/{control_id}/network-policy-checks.json", policy_checks, "Non-invasive Docker policy checks."))

    if host_probe.ok and not failures:
        return Result(
            control_id,
            Status.PARTIAL,
            "Live Docker Sandbox host-canary separation and configured network decisions were observed; the complete control also covers credential delivery, compute, duration, process count, persistence and retained state.",
            ["This evaluator intentionally does not promote the broader CON-03 requirement to PASS from two boundary probes."],
            ev,
            "docker-sbx",
        )
    details = failures[:]
    if not host_probe.ok:
        details.append("host filesystem canary was visible inside the sandbox or the probe failed")
    return Result(control_id, Status.FAIL, "One or more live isolation checks failed.", details, ev, "docker-sbx")


def _capability_profiles(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    profile = get_path(cfg, "sandbox.capability_profile", {})
    evidence = store.write_json(f"controls/{control_id}/capability-profile.json", profile, "Declared use-case capability profile.")
    if not profile:
        return Result(control_id, Status.MANUAL, "No bounded capability profile is declared.", evidence=[evidence], evaluator="profile")
    required = ["id", "version", "use_case", "owner"]
    missing = [x for x in required if not profile.get(x)]
    if missing:
        return Result(control_id, Status.FAIL, "Capability profile metadata is incomplete.", missing, [evidence], "profile")
    _trace(ctx, "capability.profile", control_id=control_id, action="validate-profile", target=str(profile.get("id")), result="partial")
    if exists("sbx"):
        org = run(["sbx", "policy", "ls", "--source", "org", "--json"])
        evidence_org = store.write_text(f"controls/{control_id}/org-policy.json", org.stdout or org.stderr, "Observed organization policy state.")
        if org.ok and org.stdout.strip() not in ("", "[]", "null"):
            return Result(control_id, Status.PARTIAL, "A versioned use-case profile is declared and organization policy state was observed, but this adapter does not yet prove that the exact profile is centrally assigned to the assessed team/use case.", ["Generic organization policy presence is deliberately not treated as CON-04 PASS."], [evidence, evidence_org], "profile")
        return Result(control_id, Status.PARTIAL, "A versioned use-case profile is declared, but centrally governed assignment was not observed.", evidence=[evidence, evidence_org], evaluator="profile")
    return Result(control_id, Status.PARTIAL, "A versioned use-case profile is declared; live central-governance evidence requires sbx.", evidence=[evidence], evaluator="profile")


def _mcp_policy_design(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    files = get_path(cfg, "assessment.mcp_policy_files", [])
    if not files:
        return Result(control_id, Status.MANUAL, "No MCP Cedar policy files are configured for static evidence.", evaluator="mcp-policy-static")
    analyses = []
    errors = []
    for raw in files:
        path = Path(str(raw))
        if not path.is_absolute():
            path = Path.cwd() / path
        if not path.exists():
            errors.append(f"missing policy file: {raw}")
            continue
        analyses.append(analyze_policy(path).to_dict())
    evidence = store.write_json(f"controls/{control_id}/mcp-policy-analysis.json", {"analyses": analyses, "errors": errors}, "Static analysis of configured Docker MCP Cedar policy examples.")
    if errors or not analyses:
        return Result(control_id, Status.FAIL, "Configured MCP policy evidence could not be analyzed.", errors, [evidence], "mcp-policy-static")

    broad = any(a["has_actionless_permit"] for a in analyses)
    registration = any(a["has_registration_scope"] and a["has_identity_url_binding"] for a in analyses)
    tools = any(a["has_tool_scope"] for a in analyses)
    approval = any(a["has_approval_guard"] for a in analyses)
    forbid = any(a["forbid_statements"] for a in analyses)
    _trace(ctx, "mcp.policy.static-analysis", control_id=control_id, action="analyze-cedar", target=";".join(map(str, files)), decision="scoped" if not broad else "broad", result="partial", attributes={"registration_binding": registration, "tool_scope": tools, "approval_guard": approval, "forbid": forbid})

    if broad:
        return Result(control_id, Status.FAIL, "The configured MCP policy contains an actionless permit that broadly allows governed MCP activity.", ["Use an allowlist posture for this reference implementation."], [evidence], "mcp-policy-static")
    if control_id == "AUT-02":
        if registration and tools:
            return Result(control_id, Status.PARTIAL, "MCP registration identity and tool use are statically scoped, but task/resource/time-bound authority is not proven end-to-end.", ["Live organization-policy evaluation evidence is still required."], [evidence], "mcp-policy-static")
    if control_id == "AUT-05":
        if approval:
            return Result(control_id, Status.PARTIAL, "The policy contains an MCP @requireApproval guard, but Docker documents this as same-client confirmation rather than independent administrator approval or separation of duties.", ["Do not treat MCP elicitation alone as full AUT-05 evidence."], [evidence], "mcp-policy-static")
    if control_id == "AUT-06":
        if registration and tools and forbid:
            return Result(control_id, Status.PARTIAL, "The reference policy is allowlist-oriented and contains explicit forbids; live fail-closed enforcement still requires organization governance and runtime audit evidence.", evidence=[evidence], evaluator="mcp-policy-static")
    return Result(control_id, Status.PARTIAL, "MCP policy design evidence is present but does not fully satisfy this broader authorization control.", evidence=[evidence], evaluator="mcp-policy-static")


def _action_attribution(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    events = read_trace(Path(ctx["trace_path"]))
    docker_events = [e for e in events if e.get("event_type") == "docker.audit"]
    dimensions = {
        "agent": any(e.get("attributes", {}).get("agent") for e in docker_events),
        "action": any(e.get("action") for e in docker_events),
        "target": any(e.get("target") for e in docker_events),
        "decision": any(e.get("decision") for e in docker_events),
        "time": any(e.get("attributes", {}).get("source_timestamp") for e in docker_events),
        "audit_session": any(e.get("attributes", {}).get("audit_session_id") for e in docker_events),
    }
    evidence = store.write_json(
        f"controls/{control_id}/action-attribution.json",
        {"docker_audit_event_count": len(docker_events), "dimensions": dimensions},
        "Attribution dimensions observed from Docker AI Governance audit records joined into the lab trace.",
    )
    extra = [evidence]
    if ctx.get("docker_audit_evidence") is not None:
        extra.append(ctx["docker_audit_evidence"])
    if not docker_events:
        return Result(
            control_id,
            Status.MANUAL,
            "No Docker AI Governance audit records were ingested for action attribution.",
            ["Enable assessment.docker_audit and, for strong correlation, select a specific audit_session_id."],
            extra,
            "docker-audit",
        )
    missing = [name for name, present in dimensions.items() if not present]
    if missing:
        return Result(control_id, Status.FAIL, "Ingested Docker audit evidence is missing core attribution dimensions.", missing, extra, "docker-audit")
    return Result(
        control_id,
        Status.PARTIAL,
        "Docker audit evidence attributes governed actions to an agent, action, target, decision, source time and audit session; binding to this exact business task/delegation remains unproven.",
        [f"{len(docker_events)} Docker audit events ingested."],
        extra,
        "docker-audit",
    )


def _agent_native_telemetry(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    events = read_trace(Path(ctx["trace_path"]))
    dimensions = {
        "run_id": any(e.get("run_id") for e in events),
        "task_id": any(e.get("task_id") for e in events),
        "policy_decision": any(e.get("event_type") == "policy.decision" for e in events),
        "action": any(e.get("action") for e in events),
        "target": any(e.get("target") for e in events),
        "result": any(e.get("result") for e in events),
        "mcp_tool_invocation": any(e.get("event_type") == "mcp.tool" for e in events),
        "model_identity": any(e.get("attributes", {}).get("model") for e in events),
    }
    evidence = store.write_json(f"controls/{control_id}/telemetry-coverage.json", {"event_count": len(events), "dimensions": dimensions}, "Coverage of the normalized hash-chained run trace.")
    core = ["run_id", "task_id", "action", "target", "result"]
    if not all(dimensions[k] for k in core):
        return Result(control_id, Status.FAIL, "The run trace is missing core telemetry dimensions.", [k for k in core if not dimensions[k]], [evidence], "trace-ledger")
    missing = [k for k, v in dimensions.items() if not v]
    return Result(control_id, Status.PARTIAL, "The lab records normalized run/action/policy evidence, but a real model→MCP→target trace has not yet been observed in this environment.", missing, [evidence], "trace-ledger")


def _correlation(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    events = read_trace(Path(ctx["trace_path"]))
    run_ids = sorted({str(e.get("run_id")) for e in events})
    sequences = [e.get("sequence") for e in events]
    evidence = store.write_json(
        f"controls/{control_id}/correlation-evidence.json",
        {"run_ids": run_ids, "event_count": len(events), "first_sequence": sequences[0] if sequences else None, "last_sequence": sequences[-1] if sequences else None},
        "Stable run identifier and sequence evidence from the trace ledger.",
    )
    if run_ids != [ctx["run_id"]]:
        return Result(control_id, Status.FAIL, "Trace events do not share exactly one assessment run identifier.", run_ids, [evidence], "trace-ledger")
    return Result(control_id, Status.PARTIAL, "All lab-generated events are correlated by one stable run identifier and ordered hash chain; external MCP/model/target-system telemetry is not yet joined.", evidence=[evidence], evaluator="trace-ledger")


def _intent_outcome(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    events = read_trace(Path(ctx["trace_path"]))
    task_id = str(get_path(cfg, "assessment.task_id", ""))
    intent = str(get_path(cfg, "assessment.intent", get_path(cfg, "agent.purpose", "")))
    material = [e for e in events if e.get("task_id") == task_id and e.get("result")]
    evidence = store.write_json(f"controls/{control_id}/intent-outcome-map.json", {"task_id": task_id, "intent": intent, "material_events": material[-25:]}, "Run-scoped intent-to-observed-result mapping.")
    if not task_id or not intent:
        return Result(control_id, Status.FAIL, "Task intent is not sufficiently declared.", evidence=[evidence], evaluator="intent-outcome")
    if material:
        return Result(control_id, Status.PARTIAL, "Declared intent is linked to run-scoped observed results, but target-system business outcomes and approvals are not yet captured end-to-end.", [f"{len(material)} material trace events linked to task {task_id}."], [evidence], "intent-outcome")
    return Result(control_id, Status.MANUAL, "No material result events were linked to the declared task.", evidence=[evidence], evaluator="intent-outcome")


def _evidence_integrity(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    trace_ok, trace_errors = verify_trace(Path(ctx["trace_path"]))
    marker = store.write_json(
        f"controls/{control_id}/integrity-capabilities.json",
        {
            "file_manifest": "sha256",
            "event_ledger": "sha256-hash-chain",
            "trace_verified_at_assessment": trace_ok,
            "trace_errors": trace_errors,
            "run_id": ctx["run_id"],
            "retention": get_path(cfg, "assessment.evidence.retention", "not-declared"),
        },
        "Evidence-integrity capabilities implemented by the lab.",
    )
    if not trace_ok:
        return Result(control_id, Status.FAIL, "The trace ledger failed its hash-chain verification.", trace_errors, [marker], "evidence-integrity")
    return Result(control_id, Status.PARTIAL, "Evidence is protected by a per-file SHA-256 manifest and an append-only SHA-256 event hash chain; access control, encryption, deletion and legal-hold workflows remain outside the lab.", evidence=[marker], evaluator="evidence-integrity")


def _adversarial(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    scenarios = get_path(cfg, "assessment.adversarial_scenarios", [])
    plan_evidence = store.write_json(f"controls/{control_id}/scenario-plan.json", scenarios, "Declared adversarial scenario plan.")
    if not scenarios:
        return Result(control_id, Status.MANUAL, "No adversarial scenarios are declared.", evidence=[plan_evidence], evaluator="adversarial")
    results, run_evidence = run_scenarios(cfg, store, ctx)
    failed = [r for r in results if r.get("status") in {"FAIL", "ERROR"}]
    passed = [r for r in results if r.get("status") == "PASS"]
    skipped = [r for r in results if r.get("status") == "SKIP"]
    _trace(ctx, "validation.scenarios", control_id=control_id, action="execute-adversarial-scenarios", target="scenario-suite", result="fail" if failed else "partial", attributes={"pass": len(passed), "fail_or_error": len(failed), "skip": len(skipped)})
    if failed:
        return Result(control_id, Status.FAIL, "One or more adversarial scenarios failed or could not be evaluated safely.", [f"{r.get('id')}: {r.get('status')}" for r in failed], [plan_evidence, run_evidence], "adversarial-runner")
    if not passed:
        return Result(control_id, Status.MANUAL, "No adversarial scenario executed in this environment.", [f"{len(skipped)} scenario(s) skipped because required live surfaces were unavailable."], [plan_evidence, run_evidence], "adversarial-runner")
    details = [f"{len(passed)} scenario(s) passed"]
    if skipped:
        details.append(f"{len(skipped)} scenario(s) skipped; SKIP is never counted as PASS")
    return Result(control_id, Status.PARTIAL, "Executed adversarial scenarios met their expected outcomes; the full control also requires risk-derived coverage and re-testing after material changes.", details, [plan_evidence, run_evidence], "adversarial-runner")


def _artifact_testing(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    checks = get_path(cfg, "assessment.artifact_checks", [])
    if not checks:
        return Result(control_id, Status.MANUAL, "No artifact checks are configured.", evaluator="artifact-tests")
    rows = []
    failed = []
    for check in checks:
        args = check.get("command", []) if isinstance(check, dict) else []
        name = check.get("name", "unnamed") if isinstance(check, dict) else "unnamed"
        if not args:
            rows.append({"name": name, "status": "SKIP", "reason": "missing command"})
            failed.append(name)
            continue
        result = run(args, timeout=int(check.get("timeout", 60)))
        rows.append({"name": name, "command": args, "returncode": result.returncode, "stdout": result.stdout[-5000:], "stderr": result.stderr[-5000:]})
        _trace(ctx, "artifact.validation", control_id=control_id, action=name, target="agent-generated-artifact", decision="accept" if result.ok else "reject", result="pass" if result.ok else "fail", attributes={"returncode": result.returncode})
        if not result.ok:
            failed.append(name)
    evidence = store.write_json(f"controls/{control_id}/artifact-checks.json", rows, "Executed artifact quality/security checks.")
    if failed:
        return Result(control_id, Status.FAIL, "One or more artifact checks failed.", failed, [evidence], "artifact-tests")
    return Result(control_id, Status.PARTIAL, "Configured artifact checks passed; equivalence to the full human-produced artifact policy is not proven by this lab.", [f"{len(rows)} checks passed"], [evidence], "artifact-tests")


def _response_readiness(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    playbooks = get_path(cfg, "assessment.response_playbooks", {})
    item = playbooks.get(control_id) if isinstance(playbooks, dict) else None
    evidence = store.write_json(f"controls/{control_id}/response-playbook.json", item or {}, "Declared response procedure for this control.")
    if not item:
        return Result(control_id, Status.MANUAL, "No response playbook is declared for this capability.", evidence=[evidence], evaluator="response")
    if item.get("tested") is True and item.get("command"):
        result = run(item["command"], timeout=int(item.get("timeout", 30)))
        run_ev = store.write_json(f"controls/{control_id}/response-test.json", {"command": item["command"], "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}, "Response playbook test execution.")
        _trace(ctx, "response.test", control_id=control_id, action="execute-playbook", target=control_id, result="pass" if result.ok else "fail")
        status = Status.PARTIAL if result.ok else Status.FAIL
        summary = "Response playbook test executed successfully; end-to-end authority revocation still needs target-system evidence." if result.ok else "Response playbook test failed."
        return Result(control_id, status, summary, evidence=[evidence, run_ev], evaluator="response")
    _trace(ctx, "response.readiness", control_id=control_id, action="inspect-playbook", target=control_id, result="partial")
    return Result(control_id, Status.PARTIAL, "A response playbook is declared but not automatically tested in this run.", evidence=[evidence], evaluator="response")


def _manual(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    _trace(ctx, "control.manual", control_id=control_id, action="defer-control", target=control_id, result="manual")
    return Result(control_id, Status.MANUAL, "This version does not yet have sufficient automated evidence for this control.", evaluator="manual")


EVALUATORS: dict[str, Evaluator] = {
    "AUT-01": _action_attribution,
    "DIS-01": _manifest,
    "DIS-02": _manifest,
    "DIS-03": _manifest,
    "DIS-04": _component_registry,
    "DIS-05": _manifest,
    "DIS-06": _manifest,
    "DIS-07": _discovery_reconciliation,
    "CON-01": _admission,
    "CON-02": _toxic_combo,
    "CON-03": _sbx_isolation,
    "CON-04": _capability_profiles,
    "AUT-02": _mcp_policy_design,
    "AUT-05": _mcp_policy_design,
    "AUT-06": _mcp_policy_design,
    "OBS-01": _agent_native_telemetry,
    "OBS-02": _correlation,
    "OBS-05": _intent_outcome,
    "OBS-06": _evidence_integrity,
    "VAL-01": _adversarial,
    "VAL-03": _artifact_testing,
    "RES-01": _response_readiness,
    "RES-02": _response_readiness,
    "RES-03": _response_readiness,
    "RES-04": _response_readiness,
    "RES-05": _response_readiness,
}


def evaluate(control_id: str, cfg: dict[str, Any], store: EvidenceStore, ctx: dict[str, Any]) -> Result:
    # Make task ID available to normalized trace events without passing cfg everywhere.
    ctx["task_id"] = str(get_path(cfg, "assessment.task_id", ""))
    fn = EVALUATORS.get(control_id, _manual)
    try:
        return fn(control_id, cfg, store, ctx)
    except Exception as exc:  # assessment must degrade safely, never silently pass
        _trace(ctx, "control.error", control_id=control_id, action="evaluate-control", target=control_id, result="error", attributes={"exception": f"{type(exc).__name__}: {exc}"})
        return Result(control_id, Status.ERROR, "Evaluator raised an unexpected error.", [f"{type(exc).__name__}: {exc}"], evaluator=getattr(fn, "__name__", "unknown"))
