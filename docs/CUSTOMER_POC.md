# Customer PoC: governing an AI coding agent with evidence

## Scenario

A platform engineering organization wants to make AI coding agents available to developers while Security needs a defensible answer to four questions:

1. What agent and components are in use?
2. What can the agent reach and do?
3. What happened during governed actions?
4. Can the organization produce evidence instead of screenshots and assumptions?

The PoC uses the Agent Baseline draft as the control vocabulary and Docker Sandboxes as the execution/governance surface.

## Success criteria

| ID | Success criterion | Evidence source | Expected PoC result |
|---|---|---|---|
| S1 | assessed agent has stable ID, owners, purpose and risk context | assessment declaration | PASS |
| S2 | host-only canary is not visible from the sandbox | `sbx exec` probe | PASS when live |
| S3 | declared denied destination evaluates to deny | `sbx policy check network` | PASS when live |
| S4 | MCP reference policy is allowlist-oriented and identity-bound at registration | Cedar policy analysis | PASS scenario |
| S5 | non-read-only MCP use has an explicit confirmation guard | Cedar policy analysis | PASS scenario, partial AUT-05 |
| S6 | generated artifact checks execute and produce machine-readable results | command hooks | no failed checks |
| S7 | evidence files are SHA-256 manifested | evidence store | verified |
| S8 | normalized run trace is hash-chained and internally anchored | trace ledger | verified |
| S9 | Docker audit metadata can be ingested without persisting raw identity fields | optional AI Governance JSONL | observed when licensed/configured |
| S10 | unsupported claims remain visible | report | no implicit PASS |

## Ten-minute demo

### 1. Establish the claims boundary

```bash
abl preflight
```

Explain that the goal is not 35 green controls. The goal is reproducible evidence and honest gaps.

### 2. Run the offline-safe assessment

```bash
abl assess --config examples/agent.yaml
```

Show that the MCP policy contract and artifact checks execute while live Docker checks become `MANUAL`/`SKIP` if `sbx` is absent.

### 3. Run the Docker vertical slice

```bash
make sandbox-create
make demo
```

Show the live host-canary and network-decision evidence under `controls/CON-03/` and `controls/VAL-01/`.

### 4. Show the evidence chain

Open the HTML report and point to:

- trace event count;
- trace-head hash;
- evidence-manifest hash;
- per-control evidence paths;
- explicit `PARTIAL` and `MANUAL` explanations.

Then:

```bash
make verify
```

### 5. Optional enterprise path

If Docker AI Governance local audit delivery is available:

```bash
abl audit-summary --agent codex
```

Select the relevant `audit_session_id` in the assessment config and re-run. Show how Docker governance metadata joins the lab trace while PII-like user/org/host fields are pseudonymized before persistence.

## Discussion prompts

The PoC is intentionally designed to create useful architecture conversations:

- Which controls can be proven locally versus centrally?
- Which evidence belongs to Docker versus the target system?
- What identifier can bind prompt/task, agent, MCP policy decision and downstream outcome?
- When is MCP elicitation sufficient, and when is independent approval required?
- What evidence should be externally anchored or signed?
- What should trigger re-validation after an agent/component change?

## Non-goals

This PoC does not claim certification, complete compliance, proof of model behavior, or complete business-outcome validation. It is a reusable implementation-assessment pattern for turning agent governance requirements into testable evidence.
