# Agent Baseline Evidence Lab

**Turn the Agent Baseline v1.0-draft into reproducible implementation evidence for a real AI coding-agent environment.**

> Community project. Not an official Docker, Snyk, Keycard, or Agent Baseline project. It does **not** issue certifications or claim official conformance.

AI-agent security guidance is easy to describe and hard to prove. This lab asks a narrower, more useful question:

> **For this agent, in this environment, during this run: what can we actually prove?**

The project maps the 35 draft Agent Baseline controls to declared state, live Docker Sandboxes probes, executable adversarial scenarios, Docker MCP Cedar-policy analysis, optional Docker AI Governance audit records, artifact checks, and explicit manual gaps. Every run emits a tamper-evident evidence bundle plus JSON/HTML reports.

## Why this is different

The lab deliberately refuses shortcuts such as:

- `Docker Sandbox installed → CON-03 PASS`
- `MCP Gateway present → authorization solved`
- `audit logs exist → end-to-end attribution proven`
- `policy file exists → enforcement proven`

Instead, every control is one of:

`PASS` · `FAIL` · `PARTIAL` · `MANUAL` · `N/A` · `ERROR`

A skipped live test is **never** counted as a pass.

## Current vertical slice

### Discover

- validates agent identity, ownership, risk context, status and component inventory;
- records declared composition and effective-access intent;
- keeps runtime-vs-declared reconciliation visibly incomplete until real observed inventory exists.

### Constrain

- detects a known toxic-capability combination;
- probes Docker Sandbox presence and active network/filesystem policy state;
- performs a disposable host-canary separation check with `sbx exec`;
- evaluates required allow/deny decisions with `sbx policy check network`;
- records bounded capability-profile evidence without inferring assignment from generic policy presence.

### Authorize

- statically analyzes Docker MCP Cedar policy posture;
- detects broad actionless permits, registration identity binding, tool/resource/prompt scope, approval guards and local-stdio forbids;
- can ingest Docker AI Governance audit events for observed action attribution;
- keeps JIT credentials, delegation attenuation, step-up and proof-of-possession manual until evidence exists.

### Observe

- creates an append-only, SHA-256 hash-chained normalized trace;
- joins Docker AI Governance metadata events when local audit delivery is enabled;
- pseudonymizes username, email, org and hostname before persistence;
- correlates all lab events by stable run ID;
- writes a per-file SHA-256 evidence manifest;
- supports external manifest/trace-head pins during verification.

### Validate

- executes adversarial scenarios, not just a scenario plan;
- currently supports live host-canary, live network-policy decision and offline MCP-policy-contract scenarios;
- executes agent-generated artifact tests and Dockerfile security contracts.

### Respond

- supports declared/testable response-playbook hooks;
- refuses to treat a written playbook as proof of credential revocation, quarantine or impact scoping.

## Architecture

```text
                    Agent Baseline v1.0-draft
                             control IDs
                                  │
                                  ▼
                         ┌───────────────────┐
 declared state ────────►│  Evidence Engine  │◄──────── Docker `sbx`
                         └─────────┬─────────┘
                                   │
             ┌─────────────────────┼─────────────────────┐
             │                     │                     │
             ▼                     ▼                     ▼
      Cedar policy            Scenario runner       Docker AI Governance
      static analysis         safe/live probes      local audit JSONL
             │                     │                     │
             └─────────────────────┼─────────────────────┘
                                   ▼
                         normalized run trace
                         SHA-256 hash chain
                                   │
                                   ▼
                         run-scoped evidence
                         SHA-256 file manifest
                                   │
                       ┌───────────┴───────────┐
                       ▼                       ▼
                  JSON report              HTML report
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/DOCKER_EVIDENCE_SOURCES.md`](docs/DOCKER_EVIDENCE_SOURCES.md).

## Five-minute path

```bash
make install
make preflight
make demo
make verify
```

The offline path is intentionally useful. Without `sbx`, live scenarios become `SKIP`/`MANUAL`; the MCP policy contract and artifact checks still execute.

To collect the Docker Sandboxes vertical slice:

```bash
make sandbox-create
make demo
make verify
```

`sandbox-create` adds only a **sandbox-scoped** deny for the canary destination. It does not widen or replace global policy.

## Real Codex-in-Sandbox execution

The V0.4 live path runs a real coding task in a **disposable copy** of the sample workspace and feeds that exact execution back into the assessment:

```bash
make live-demo
```

The live-run capsule stores prompt/output digests instead of raw content by default, captures before/after workspace hashes, Docker Sandbox policy observations and the agent task result, then runs artifact checks against the **agent-modified workspace** rather than the original template.

For the MCP vertical slice, register Docker's public DHI MCP endpoint and run Codex with it pre-loaded through the Docker Sandboxes MCP Gateway:

```bash
make mcp-register-dhi
make live-demo-mcp
```

The full configuration uses `policies/mcp/dhi-readonly.cedar`: registration is identity-bound to `https://dhi.io/mcp`, read-only tools are allowed, non-read-only tools are forbidden, local-stdio registration is forbidden, and dynamic gateway expansion is blocked. The Cedar file is **reference policy evidence** until installed and enforced through Docker AI Governance.

See [`docs/LIVE_AGENT_RUN.md`](docs/LIVE_AGENT_RUN.md) for the execution, privacy and governance model.

## Evidence output

```text
evidence/abl-<timestamp>/
├── inputs/
│   └── assessment-config.yaml
├── controls/
│   ├── AUT-01/...
│   ├── CON-03/...
│   ├── VAL-01/...
│   └── ...
├── observations/
│   └── docker-ai-governance-audit.json   # only when enabled
├── trace/
│   └── events.ndjson
├── assessment.json
└── manifest.sha256.json

reports/
├── abl-<timestamp>.json
└── abl-<timestamp>.html
```

Every evidence item includes a digest in the report. The HTML report shows the trace head, event count, manifest digest and Docker audit-event count as a compact **evidence trust chain**.

## Tamper-evidence model

`abl verify` checks three layers:

1. every file recorded by `manifest.sha256.json` still matches its SHA-256;
2. every trace event links to the hash of the previous event;
3. the final trace hash and event count match the anchors recorded in `assessment.json`.

For a stronger boundary, pin one or both hashes outside the evidence bundle:

```bash
abl verify evidence/abl-... \
  --expected-manifest-sha256 <sha256> \
  --expected-trace-head <sha256>
```

This project calls the structure **tamper-evident**, not tamper-proof. It does not yet digitally sign evidence bundles.

## Docker AI Governance audit ingestion

Docker AI Governance local audit delivery writes finalized `.jsonl` records containing metadata such as principal, action, target, decision, timestamp, audit session, agent and action type. The lab can ingest them without persisting raw user/org/host identity fields.

Enable it in the assessment config:

```yaml
assessment:
  docker_audit:
    enabled: true
    # optional; otherwise the documented OS default is used
    path: ~/Library/Logs/com.docker.sandboxes/sandboxes/auditkit/
    # strongly recommended when presenting attribution evidence
    audit_session_id: <docker-audit-session-id>
    agent: codex
```

Preview available records without adding them to an assessment:

```bash
abl audit-summary --agent codex
```

Local audit delivery is an optional Docker AI Governance capability and is not required for the community/offline path.

## Adversarial scenarios

The sample config currently defines:

| Scenario | Execution | Expected outcome |
|---|---|---|
| host filesystem separation | live `sbx exec` | host canary absent |
| denied egress decision | live `sbx policy check network` | deny |
| MCP allowlist contract | offline Cedar static analysis | scoped allowlist posture |

Results are stored under `controls/VAL-01/scenario-results.json`.

## MCP policy evidence

The reference policy follows Docker's current MCP governance model:

- explicit server registration permit bound to registered name + `identityURL`;
- read-only tool use permit;
- `@requireApproval` for non-read-only tools;
- resource/prompt permits scoped to the registered server;
- explicit registration forbid for `local-stdio` host-run servers.

The lab intentionally treats MCP elicitation as a confirmation guardrail, **not** proof of independent administrator approval or separation of duties.

## Baseline drift

The Agent Baseline remains a draft. Before a customer-facing run:

```bash
make baseline-sync
```

The command fetches and hashes the authoritative upstream `whitepaper/controls.yaml`, compares the permanent IDs and reports drift. Requirement prose remains upstream rather than being silently forked here.

## Customer PoC

[`docs/CUSTOMER_POC.md`](docs/CUSTOMER_POC.md) turns the repository into a reusable customer exercise: scenario, success criteria, evidence expectations, a 10-minute demo path and explicit claims boundary.

## Development

```bash
make install
make test
make lint
```

CI runs unit tests, sample-app tests, the offline-safe assessment, bundle verification and uploads the generated assessment as a workflow artifact.

## Project status

This is an implementation lab, not a finished assurance product. The most important next milestones are:

1. collect the first real Docker AI Governance MCP `tool_invocation` + `tool_execution` pair from the DHI live demo;
2. propagate or derive a stronger cross-system correlation key between the agent task and Docker audit session;
3. add tested stop/quarantine response exercises;
4. sign evidence anchors with a portable signing mechanism;
5. submit upstream Agent Baseline feedback only when a reproducible implementation gap is found.

See [`docs/ROADMAP.md`](docs/ROADMAP.md).

## License

Apache-2.0 for this repository's code. Agent Baseline materials remain under their upstream licenses and ownership; authoritative control requirements are not vendored here.
