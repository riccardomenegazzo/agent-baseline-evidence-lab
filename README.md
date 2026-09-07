# Agent Baseline Evidence Lab

[![CI](https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/actions/workflows/ci.yml)

**Turn the Agent Baseline v1.0-draft into reproducible implementation evidence for a real AI coding-agent environment.**

> Community project. Not an official Docker, Snyk, Keycard, or Agent Baseline project. It does **not** issue certifications or claim official conformance.

AI-agent security guidance is easy to describe and hard to prove. This lab asks a narrower question:

> **For this agent, in this environment, during this run: what can we actually prove?**

The lab maps the 35 draft Agent Baseline controls to declared state, live Docker Sandboxes probes, executable adversarial scenarios, Docker MCP Cedar-policy analysis, optional Docker AI Governance audit records, artifact validation, response drills, and explicit manual gaps.

Every assessment produces evidence rather than a marketing score: a normalized hash-chained trace, a SHA-256 evidence manifest, JSON/HTML reports, and an unsigned in-toto-style run attestation.

## The manager-facing path

After installation and Docker Sandboxes authentication, the complete community demo is one command:

```bash
make interview-demo
```

It executes this evidence flow:

```text
real coding task
      │
      ▼
Codex in a unique Docker Sandbox
      │
      ▼
Agent Baseline assessment
      │
      ├── live sbx boundary probes
      ├── adversarial scenarios
      ├── artifact validation
      ├── MCP policy evidence
      └── optional Docker audit evidence
      │
      ▼
immutable assessment bundle
      │
      ▼
disposable response drill
      ├── create sandbox-scoped test credential binding
      ├── observe binding
      ├── revoke binding
      ├── verify binding is absent
      ├── stop the exact sandbox from this run
      └── verify stopped state
      │
      ▼
response evidence
      │
      ▼
assessment SHA-256 ─┐
                    ├── response-link statement
response SHA-256 ───┘
      │
      ▼
independent link verification
      │
      ▼
remove only the unique disposable sandbox
```

The command never substitutes a fixed sandbox name: the response drill receives the **actual unique sandbox identity returned by the live agent run**.

For the Docker MCP + AI Governance audit variant:

```bash
make mcp-register-dhi
make interview-demo-mcp
```

For a zero-mutation orchestration check:

```bash
make interview-demo-dry-run
```

Dry-run mode is required to report all response claims as false and is exercised in CI.

## Why this is different

The lab deliberately refuses shortcuts such as:

- `Docker Sandbox installed → CON-03 PASS`
- `MCP Gateway present → authorization solved`
- `audit logs exist → end-to-end attribution proven`
- `policy file exists → enforcement proven`
- `sbx stop returned 0 → containment proven`
- `credential binding removed → upstream provider token revoked`

Instead, every Agent Baseline control is one of:

`PASS` · `FAIL` · `PARTIAL` · `MANUAL` · `N/A` · `ERROR`

A skipped live test is **never** counted as a pass.

The project distinguishes three kinds of evidence:

1. **declared evidence** — configuration and design intent;
2. **observed evidence** — runtime state, policy decisions, audit events and postconditions;
3. **linked evidence** — immutable artifacts correlated by cryptographic digest.

## Current vertical slice

### Discover

- validates agent identity, ownership, risk context, status and component inventory;
- records declared composition and effective-access intent;
- observes Docker MCP registrations when available;
- keeps runtime-vs-declared reconciliation incomplete until real observed inventory exists.

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
- maps Docker MCP evaluations to policy-decision and semantic MCP trace events;
- keeps JIT credentials, delegation attenuation, step-up and proof-of-possession manual until evidence exists.

### Observe

- creates an append-only SHA-256 hash-chained normalized trace;
- joins finalized Docker AI Governance metadata events when configured;
- recognizes observed `tool_invocation` / `tool_execution` as MCP activity rather than inferring tool use from configuration;
- pseudonymizes username, email, organization and hostname before persistence;
- preserves Docker audit event/session correlation keys;
- writes a per-file SHA-256 evidence manifest;
- emits an unsigned in-toto-style run attestation;
- supports external hash pins during verification.

### Validate

- executes adversarial scenarios rather than storing only a scenario plan;
- supports live host-canary and network-policy decision scenarios;
- includes an offline MCP policy contract scenario;
- executes tests against the **agent-modified disposable workspace**;
- validates the sample Dockerfile security contract;
- includes negative provenance tests where intentional evidence mutation must break verification.

### Respond

- keeps response mutation outside normal assessment execution;
- can verify the named sandbox reached a stopped state rather than trusting command success alone;
- can create and revoke a unique **sandbox-scoped disposable custom-secret binding** without using a real provider credential;
- verifies the binding was observed before removal and absent after removal;
- explicitly does **not** equate Docker-side binding removal with upstream provider token/session invalidation;
- links response evidence to the original immutable assessment bundle by SHA-256;
- independently re-verifies the assessment-to-response link.

## Evidence architecture

```text
                         Agent Baseline v1.0-draft
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
                         assessment evidence
                         SHA-256 file manifest
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
         JSON report          HTML report       run attestation
                                                (unsigned)
                                   │
                                   │ SHA-256
                                   ▼
                           response-link statement
                                   ▲
                                   │ SHA-256
                         response drill evidence
```

See:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/DOCKER_EVIDENCE_SOURCES.md`](docs/DOCKER_EVIDENCE_SOURCES.md)
- [`docs/RUN_ATTESTATION.md`](docs/RUN_ATTESTATION.md)
- [`docs/RESPONSE_DRILL.md`](docs/RESPONSE_DRILL.md)
- [`docs/INTERVIEW_DEMO.md`](docs/INTERVIEW_DEMO.md)

## Quick start

```bash
make install
make preflight
make demo
make verify
```

The offline path remains intentionally useful. Without `sbx`, live scenarios become `SKIP`/`MANUAL`; policy-contract and artifact checks still execute.

A real Codex-in-Sandbox run:

```bash
make live-demo
```

The live capsule stores prompt/output digests instead of raw content by default, captures workspace hashes before and after execution, Docker Sandbox observations and the agent task result, then evaluates the files the agent actually modified.

## MCP vertical slice

Register Docker's public DHI MCP endpoint:

```bash
make mcp-register-dhi
```

Then run:

```bash
make live-demo-mcp
```

The MCP configuration uses `policies/mcp/dhi-readonly.cedar` as reference policy evidence. Static policy analysis is not promoted to enforcement evidence unless the relevant runtime decision is observed.

When Docker AI Governance audit records are available, `tool_invocation` and `tool_execution` events are normalized as observed MCP activity, while source-level Docker audit events remain preserved through their correlation identifiers.

See [`docs/LIVE_AGENT_RUN.md`](docs/LIVE_AGENT_RUN.md).

## Response evidence

The basic containment drill is explicit and affects only the named demo sandbox:

```bash
make response-drill
```

The stronger exercise adds disposable credential-binding revocation:

```bash
make response-drill-full
```

It uses generated random test material, not a real OpenAI/GitHub/cloud credential.

Verify the response artifact:

```bash
python3 -m agent_baseline_lab.response_verify \
  .abl/response/abl-demo-stop.json \
  --sandbox abl-demo \
  --require-revocation
```

Link it to the latest verified assessment without mutating either artifact:

```bash
make response-link
make response-link-verify
```

The link statement is unsigned and binds:

```text
assessment manifest SHA-256
response evidence SHA-256
assessment run ID
assessment trace head
sandbox identity
response claims
```

This provides digest-level correlation and tamper evidence. Authenticity still requires an external signature or externally pinned digest.

## Evidence output

```text
agent-runs/
└── agent-<timestamp>-<id>/
    ├── session.json
    ├── workspace-before.json
    ├── workspace-after.json
    ├── workspace-changes.json
    ├── docker-observations.json
    └── manifest.sha256.json

evidence/
└── abl-<timestamp>/
    ├── inputs/
    ├── controls/
    ├── observations/
    ├── trace/events.ndjson
    ├── assessment.json
    └── manifest.sha256.json

.abl/response/
└── <session-id>.json

reports/
├── abl-<timestamp>.json
├── abl-<timestamp>.html
├── abl-<timestamp>.attestation.json
├── abl-<timestamp>.response-link.json
└── abl-<timestamp>.interview-demo.json
```

## Tamper-evidence and provenance

`abl verify` checks:

1. every file recorded by `manifest.sha256.json` still matches its digest;
2. every trace event links to the hash of the previous event;
3. final trace hash and event count match anchors in `assessment.json`.

For an external boundary:

```bash
abl verify evidence/abl-... \
  --expected-manifest-sha256 <sha256> \
  --expected-trace-head <sha256>
```

Verify the unsigned run attestation independently:

```bash
abl verify-attestation \
  reports/abl-....attestation.json \
  evidence/abl-.../manifest.sha256.json
```

The project calls these structures **tamper-evident**, not tamper-proof.

## Docker AI Governance audit ingestion

Enable optional local audit ingestion in an assessment config:

```yaml
assessment:
  docker_audit:
    enabled: true
    path: ~/Library/Logs/com.docker.sandboxes/sandboxes/auditkit/
    audit_session_id: <docker-audit-session-id>
    agent: codex
```

Preview records without adding them to an assessment:

```bash
abl audit-summary --agent codex
```

In-progress `.tmp` records are not treated as finalized evidence. Zero selected finalized events is never interpreted as proof that no governed action occurred.

## Adversarial scenarios

The sample configuration includes:

| Scenario | Execution | Expected outcome |
|---|---|---|
| host filesystem separation | live `sbx exec` | host canary absent |
| denied egress decision | live `sbx policy check network` | deny |
| MCP allowlist contract | offline Cedar analysis | scoped policy posture |

Results are stored under `controls/VAL-01/scenario-results.json`.

## Baseline drift

The Agent Baseline remains a draft. Before a customer-facing run:

```bash
make baseline-sync
```

The command fetches and hashes the authoritative upstream controls file, compares permanent control IDs and reports drift. Requirement prose remains upstream rather than being silently forked into this repository.

## Customer PoC

[`docs/CUSTOMER_POC.md`](docs/CUSTOMER_POC.md) turns the repository into a reusable customer exercise with scenario, success criteria, evidence expectations, demo flow and explicit claims boundaries.

For the five-minute technical-manager walkthrough, use [`docs/INTERVIEW_DEMO.md`](docs/INTERVIEW_DEMO.md).

## Development and CI

```bash
make install
make test
make lint
make interview-demo-dry-run
```

CI validates:

- Ruff quality gate;
- framework unit tests;
- sample-app tests;
- metadata-only live-run capsule;
- response-drill non-mutation contract;
- explicit anti-false-claim assertions;
- full interview orchestration in dry-run mode;
- offline Agent Baseline assessment;
- evidence bundle integrity;
- run-attestation subject binding;
- generated workflow evidence artifacts.

## Project status — v0.6.0

The repository is an implementation lab, not a finished assurance product. The highest-value next milestones are:

1. collect a real Docker AI Governance MCP `tool_invocation` + `tool_execution` pair from the DHI live flow on a governed Docker organization;
2. derive or propagate a stronger correlation key between the coding task, Docker audit session and downstream MCP action;
3. add a portable signing backend for assessment, response and response-link attestations;
4. extend response evidence from sandbox-local binding revocation to optional provider-specific revocation adapters without weakening the claims boundary;
5. contribute implementation evidence upstream where it adds information beyond existing Agent Baseline discussion.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) and [`docs/UPSTREAM_FEEDBACK.md`](docs/UPSTREAM_FEEDBACK.md).

## License

Apache-2.0 for this repository's code. Agent Baseline materials remain under their upstream licenses and ownership; authoritative control requirements are not vendored here.
