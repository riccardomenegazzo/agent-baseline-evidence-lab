# Agent Baseline Evidence Lab

**Turn the Agent Baseline v1.0-draft into reproducible implementation evidence for a real AI coding-agent environment.**

> Community project. Not an official Docker, Snyk, Keycard, or Agent Baseline project. It does **not** issue certifications or claim official conformance.

AI-agent security guidance is easy to describe and hard to prove. This lab asks a narrower, more useful question:

> **For this agent, in this environment, during this run: what can we actually prove?**

The project maps the 35 draft Agent Baseline controls to declared state, live Docker Sandboxes probes, executable adversarial scenarios, Docker MCP Cedar-policy analysis, optional Docker AI Governance audit records, artifact checks, and explicit manual gaps. Every run emits a tamper-evident evidence bundle, JSON/HTML reports, and an unsigned in-toto-style run attestation.

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
- ingests Docker AI Governance audit events for observed action attribution when available;
- maps Docker MCP evaluations to both `policy.decision` and semantic MCP trace events while retaining the original source-level `docker.audit` event;
- keeps JIT credentials, delegation attenuation, step-up and proof-of-possession manual until evidence exists.

### Observe

- creates an append-only, SHA-256 hash-chained normalized trace;
- joins Docker AI Governance metadata events when local audit delivery is enabled;
- recognizes observed `tool_invocation` / `tool_execution` as `mcp.tool`, rather than inferring tool use from MCP configuration alone;
- pseudonymizes username, email, org and hostname before persistence;
- correlates all lab events by stable run ID and preserves Docker `audit_event_id` / `audit_session_id` as source correlation keys;
- writes a per-file SHA-256 evidence manifest;
- emits an unsigned in-toto-style run attestation binding the evidence manifest to the observed task/runtime facts;
- supports external hash pins during bundle and attestation verification.

### Validate

- executes adversarial scenarios, not just a scenario plan;
- currently supports live host-canary, live network-policy decision and offline MCP-policy-contract scenarios;
- executes agent-generated artifact tests and Dockerfile security contracts;
- includes negative provenance tests that deliberately mutate the evidence manifest and require attestation verification to fail.

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
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
         JSON report          HTML report       run attestation
                                                (unsigned)
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/DOCKER_EVIDENCE_SOURCES.md`](docs/DOCKER_EVIDENCE_SOURCES.md), and [`docs/RUN_ATTESTATION.md`](docs/RUN_ATTESTATION.md).

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

For a manager-facing walkthrough, see [`docs/INTERVIEW_DEMO.md`](docs/INTERVIEW_DEMO.md).

## Real Codex-in-Sandbox execution

The v0.5 live path runs a real coding task in a **disposable copy** of the sample workspace and feeds that exact execution back into the assessment:

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

When Docker AI Governance audit records are available, the lab distinguishes MCP configuration from **observed MCP activity**: `tool_invocation` and `tool_execution` records are normalized into `mcp.tool` trace events, while evaluation records also produce `policy.decision`. The original Docker event remains represented as `docker.audit`, linked through the same `audit_event_id`.

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
├── abl-<timestamp>.html
└── abl-<timestamp>.attestation.json
```

Every evidence item includes a digest in the report. The HTML report shows the trace head, event count, manifest digest and Docker audit-event count as a compact **evidence trust chain**.

## Tamper-evidence and attestation model

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

Every assessment also emits an unsigned in-toto-style statement whose subject is the evidence manifest. Verify the binding independently:

```bash
abl verify-attestation \
  reports/abl-....attestation.json \
  evidence/abl-.../manifest.sha256.json
```

Or provide an attestation digest stored outside the evidence producer's boundary:

```bash
abl verify-attestation \
  reports/abl-....attestation.json \
  evidence/abl-.../manifest.sha256.json \
  --expected-attestation-sha256 <sha256>
```

This project calls the structure **tamper-evident**, not tamper-proof. The attestation explicitly records `signed: false`; authenticity still requires an external trust anchor or a future signing backend.

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

The audit summary also reports in-progress `.tmp` files. Those files are **not** ingested as evidence because Docker documents them as incomplete. If a live run has just finished and its records have not yet rotated to finalized `.jsonl`, re-run the generated assessment config after finalization instead of treating zero selected records as proof that no governed action occurred.

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

CI runs lint, unit tests, sample-app tests, a metadata-only live-run capsule, the offline-safe assessment, bundle verification, attestation verification and uploads generated evidence as a workflow artifact.

## Project status

This is an implementation lab, not a finished assurance product. The most important next milestones are:

1. collect the first real Docker AI Governance MCP `tool_invocation` + `tool_execution` pair from the DHI live demo on a governed Docker organization;
2. propagate or derive a stronger cross-system correlation key between the agent task and Docker audit session;
3. add tested stop/quarantine response exercises;
4. add a portable signing backend for externally anchored attestations;
5. contribute implementation evidence upstream where it adds information beyond existing Agent Baseline discussions.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) and [`docs/UPSTREAM_FEEDBACK.md`](docs/UPSTREAM_FEEDBACK.md).

## License

Apache-2.0 for this repository's code. Agent Baseline materials remain under their upstream licenses and ownership; authoritative control requirements are not vendored here.
