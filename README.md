# Agent Baseline Evidence Lab

[![CI](https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/actions/workflows/ci.yml)

**Turn the Agent Baseline v1.0-draft into reproducible implementation evidence for a real AI coding-agent environment.**

> Community project. Not an official Docker, Snyk, Keycard, or Agent Baseline project. It does **not** issue certifications or claim official conformance.

AI-agent security guidance is easy to describe and much harder to prove. This lab asks a narrower question:

> **For this agent, in this environment, during this run: what can we actually prove?**

The repository maps the 35 draft Agent Baseline controls to declared state, Docker Sandboxes probes, executable adversarial scenarios, Docker MCP Cedar-policy analysis, optional Docker AI Governance audit records, artifact validation, response drills, cryptographic evidence, and explicit manual gaps.

Every assessment produces evidence rather than a marketing score.

---

## The manager-facing path

For the community path, after installation and Docker Sandboxes authentication:

```bash
make interview-demo
```

The flow is intentionally evidence-first:

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
      ├── response-link by SHA-256
      ├── quarantine registry entry
      └── digest-only incident bundle
      │
      ▼
independent verification
      │
      ▼
remove only the unique disposable sandbox
```

The response flow uses the **actual unique sandbox identity created for the live agent run**. It never substitutes a fixed sandbox name.

For Docker MCP + AI Governance audit evidence:

```bash
make mcp-register-dhi
make interview-demo-mcp
```

For a zero-mutation orchestration check:

```bash
make interview-demo-dry-run
```

Dry-run mode is required to leave positive response, quarantine, incident, and revocation claims false. CI tests that contract.

---

## Post-run assurance

After an assessment or interview flow:

```bash
make assurance-latest
```

The assurance suite is read-only. It discovers the latest local evidence and evaluates:

```text
assessment bundle integrity
        │
        ├── adversarial evidence-verifier regression matrix
        ├── credential-sensitive workspace co-change detection
        ├── behavioral drift against a retained baseline
        ├── Ed25519 attestation signature
        ├── external signing-key anchor, when present
        ├── incident-bundle digest verification
        └── quarantine-registry integrity
```

The result is written to:

```text
reports/assurance-summary.json
```

Its result semantics are deliberately different from the control assessment:

- `PASS` — executed verification succeeded;
- `FAIL` — a blocking integrity/authenticity verifier failed;
- `FINDING` — a non-blocking risk signal requires investigation;
- `NOT_RUN` — optional evidence was not available.

A behavioral change is therefore not mislabeled as a framework failure, while a corrupted bundle or invalid signature is blocking.

---

## Why this is different

The lab refuses shortcuts such as:

- `Docker Sandbox installed → CON-03 PASS`
- `MCP Gateway present → authorization solved`
- `audit logs exist → end-to-end attribution proven`
- `policy file exists → enforcement proven`
- `sbx stop returned 0 → containment proven`
- `credential binding removed → upstream provider token revoked`
- `signature verifies → signer identity is trusted`
- `hash chain verifies → source telemetry was complete`

Every Agent Baseline control is one of:

`PASS` · `FAIL` · `PARTIAL` · `MANUAL` · `N/A` · `ERROR`

A skipped live test is **never** counted as a pass.

The project distinguishes four evidence classes:

1. **declared evidence** — configuration and design intent;
2. **observed evidence** — runtime state, policy decisions, audit events and postconditions;
3. **linked evidence** — artifacts correlated by stable identifiers or cryptographic digests;
4. **externally anchored evidence** — evidence authenticated against material outside the artifact being verified.

---

## Current vertical slice

### Discover

- validates agent identity, ownership, risk context, status and component inventory;
- records declared composition and effective-access intent;
- inventories Docker MCP registrations when available;
- matches expected MCP registration name and endpoint identity;
- keeps runtime-vs-declared reconciliation incomplete until observed inventory exists.

### Constrain

- detects a known toxic-capability combination;
- probes Docker Sandbox presence and active network/filesystem policy state;
- performs a disposable host-canary separation check with `sbx exec`;
- evaluates required allow/deny decisions with `sbx policy check network`;
- provides a direct-MCP bypass probe so gateway governance and sandbox egress are not conflated;
- records bounded capability-profile evidence without inferring assignment from generic policy presence.

### Authorize

- statically analyzes Docker MCP Cedar policy posture;
- detects broad actionless permits, registration identity binding, tool/resource/prompt scope, approval guards and local-stdio forbids;
- distinguishes `invokePrimordial` permit from forbid posture;
- observes OAuth authorization metadata without storing token material;
- ingests Docker AI Governance audit events for observed action attribution when available;
- analyzes bounded evaluation → approval/deny → execution chains;
- keeps JIT credentials, delegation attenuation, step-up and proof-of-possession manual until direct evidence exists.

### Observe

- creates an append-only SHA-256 hash-chained normalized trace;
- joins finalized Docker AI Governance metadata events when configured;
- recognizes observed `tool_invocation` / `tool_execution` as MCP activity rather than inferring tool use from configuration;
- pseudonymizes username, email, organization and hostname before persistence;
- preserves Docker audit event/session correlation keys;
- supports behavioral drift baselines for destinations, tool use and event classes;
- detects credential-sensitive/code co-change from changed paths without reading secret contents;
- writes a per-file SHA-256 evidence manifest;
- emits an in-toto-style run attestation;
- supports external hash pins and Ed25519 signatures.

### Validate

- executes adversarial scenarios rather than storing only a scenario plan;
- includes live host-canary and network-policy decision scenarios;
- includes an offline MCP policy contract scenario;
- executes tests against the **agent-modified disposable workspace**;
- validates the sample Dockerfile security contract;
- includes negative provenance tests where intentional evidence mutation must break verification;
- includes a verifier attack matrix for single-file mutation, trace truncation, coordinated rewrite, and never-emitted source events.

### Respond

- keeps response mutation outside normal assessment execution;
- verifies the named sandbox reached a stopped state rather than trusting command success alone;
- can create and revoke a unique **sandbox-scoped disposable custom-secret binding** without using a real provider credential;
- explicitly distinguishes local credential-binding removal from upstream provider token/session revocation;
- provides a fail-closed provider-revocation adapter path, dry-run by default;
- links response evidence to the original immutable assessment bundle by SHA-256;
- records quarantine decisions in an append-only registry;
- builds digest-only incident manifests from assessment, response, correlation and quarantine evidence;
- provides a tested non-agent fallback validation workflow.

---

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
                                                     │
                                      optional Ed25519 signature
                                                     │
                                   ┌─────────────────┴──────────────┐
                                   ▼                                ▼
                           response-link                    external key anchor
                                   ▲
                                   │
                         response drill evidence
                                   │
                          quarantine + incident bundle
```

See:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/DOCKER_EVIDENCE_SOURCES.md`](docs/DOCKER_EVIDENCE_SOURCES.md)
- [`docs/RUN_ATTESTATION.md`](docs/RUN_ATTESTATION.md)
- [`docs/RESPONSE_DRILL.md`](docs/RESPONSE_DRILL.md)
- [`docs/INTERVIEW_DEMO.md`](docs/INTERVIEW_DEMO.md)
- [`docs/ROADMAP.md`](docs/ROADMAP.md)

---

## Quick start

```bash
make install
make preflight
make demo
make verify
make assurance-latest
```

The offline path remains intentionally useful. Without `sbx`, live scenarios become `SKIP`/`MANUAL`; policy-contract and artifact checks still execute.

A real Codex-in-Sandbox run:

```bash
make live-demo
```

The live capsule stores prompt/output digests instead of raw content by default, captures workspace hashes before and after execution, Docker Sandbox observations and the agent task result, then evaluates the files the agent actually modified.

---

## MCP assurance path

Register Docker's public DHI MCP endpoint:

```bash
make mcp-register-dhi
```

Observe and validate the registration identity:

```bash
make mcp-inventory-dhi
```

Observe OAuth state without storing token material:

```bash
make mcp-oauth-status
```

With a live sandbox, test whether direct sandbox egress can bypass the host-side MCP path:

```bash
make mcp-bypass-dhi SANDBOX=<sandbox-name>
```

Run the MCP live path:

```bash
make live-demo-mcp
```

The MCP configuration uses `policies/mcp/dhi-readonly.cedar` as reference policy evidence. Static policy analysis is never promoted to runtime enforcement evidence unless the relevant runtime decision is actually observed.

When Docker AI Governance audit records are available, `tool_invocation` and `tool_execution` events are normalized as observed MCP activity, while source-level Docker audit events remain preserved through their available correlation identifiers.

See [`docs/LIVE_AGENT_RUN.md`](docs/LIVE_AGENT_RUN.md).

---

## Response evidence

Basic containment drill:

```bash
make response-drill
```

Stronger disposable credential-binding exercise:

```bash
make response-drill-full
```

It uses generated random test material, not a real OpenAI, GitHub, or cloud credential.

Verify the response artifact:

```bash
python3 -m agent_baseline_lab.response_verify \
  .abl/response/abl-demo-stop.json \
  --sandbox abl-demo \
  --require-revocation
```

Link it to the latest verified assessment:

```bash
make response-link
make response-link-verify
```

The link binds:

```text
assessment manifest SHA-256
response evidence SHA-256
assessment run ID
assessment trace head
sandbox identity
response claims
```

For explicit provider-revocation preview without mutation:

```bash
make provider-revocation-dry
```

---

## Signing and trust anchors

Generate a local Ed25519 keypair:

```bash
make signing-keygen
```

The private key is created below `.abl/`, which is ignored by Git.

Sign and verify the latest run attestation:

```bash
make sign-latest
make verify-signature-latest
```

The signature proves authenticity relative to possession of the corresponding private key. It does **not** prove the human or organization controlling the key unless the verifier trusts the public key through an external channel.

The same key can sign a verified upstream baseline lock:

```bash
make baseline-sync
make baseline-lock-verify
make baseline-lock-sign
make baseline-lock-verify-signature
```

The baseline lock verifier recalculates source digest, control IDs, control count, version/status and catalogue drift before a signature is considered meaningful.

---

## Behavioral drift and unintended-action signals

Create a retained baseline from the latest assessment trace:

```bash
make drift-baseline
```

Compare a later run:

```bash
make drift-compare
```

Analyze the latest agent workspace delta for credential-sensitive/code co-change:

```bash
make unintended-latest
```

Neither signal reads secret file contents.

---

## Non-agent fallback

Demonstrate that validation can continue with the AI agent disabled:

```bash
make fallback-demo
```

The resulting artifact records reviewer identity, reason, validation commands, return codes and the explicit claims boundary. It proves the declared non-agent validation path executed; it does not pretend to prove a human reviewed every changed line.

---

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

.abl/
├── keys/
├── response/
├── quarantine/
└── baselines/

reports/
├── abl-<timestamp>.json
├── abl-<timestamp>.html
├── abl-<timestamp>.attestation.json
├── abl-<timestamp>.attestation.json.ed25519.json
├── abl-<timestamp>.response-link.json
├── abl-<timestamp>.incident.json
├── abl-<timestamp>.interview-demo.json
└── assurance-summary.json
```

---

## Tamper evidence, authenticity, and completeness

`abl verify` checks:

1. every file recorded by `manifest.sha256.json` still matches its digest;
2. every trace event links to the hash of the previous event;
3. final trace hash and event count match anchors in `assessment.json`.

For an external hash boundary:

```bash
abl verify evidence/abl-... \
  --expected-manifest-sha256 <sha256> \
  --expected-trace-head <sha256>
```

Verify the run attestation subject binding:

```bash
abl verify-attestation \
  reports/abl-....attestation.json \
  evidence/abl-.../manifest.sha256.json
```

The project calls these structures **tamper-evident**, not tamper-proof.

The adversarial verification matrix intentionally demonstrates a deeper limit: a coordinated producer-side rewrite can remain internally self-consistent unless an external anchor exists, and no exported artifact can prove the existence of a source event that never entered the evidence pipeline.

---

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

---

## Baseline drift

The Agent Baseline remains a draft. Before a customer-facing run:

```bash
make baseline-sync
make baseline-lock-verify
```

The project fetches and hashes the authoritative upstream controls file, compares permanent control IDs and reports drift. Requirement prose remains upstream rather than being silently forked into this repository.

---

## Evidence schema evolution

Response and interview-summary artifacts use explicit schema versions. Migration support is fail-closed:

- future unknown schema versions are rejected;
- legacy artifacts may be migrated only through known transitions;
- migrations initialize newly introduced positive claims to `false`/empty rather than inferring them.

This prevents a format upgrade from manufacturing security evidence.

---

## Customer PoC

[`docs/CUSTOMER_POC.md`](docs/CUSTOMER_POC.md) turns the repository into a reusable customer exercise with scenario, success criteria, evidence expectations, demo flow and explicit claims boundaries.

For the technical-manager walkthrough, use [`docs/INTERVIEW_DEMO.md`](docs/INTERVIEW_DEMO.md).

---

## Development and CI

```bash
make install
make test
make lint
make interview-demo-dry-run
make assurance-latest
```

CI validates, among other things:

- Ruff quality gate;
- framework unit tests;
- sample-app tests;
- metadata-only live-run capsule;
- response-drill non-mutation contract;
- provider-revocation fail-closed dry run;
- non-agent fallback execution;
- full interview orchestration in dry-run mode;
- explicit anti-false-claim assertions;
- offline Agent Baseline assessment;
- evidence bundle integrity;
- adversarial verifier matrix;
- run-attestation subject binding;
- Ed25519 signing and verification with an external CI public key;
- consolidated post-run assurance with no blocking failures.

---

## Project status — v0.7.0

The repository is an implementation and assurance lab, not a finished enterprise governance product.

Implemented and testable now:

- portable Ed25519 signing;
- baseline-source lock verification and signing;
- MCP registration identity matching;
- OAuth metadata redaction;
- direct-MCP bypass probing;
- bounded MCP governance action-chain analysis;
- drift and unintended-action detection;
- sandbox stop + disposable binding revocation evidence;
- provider-revocation adapter boundary;
- quarantine registry;
- digest-only incident bundle;
- non-agent fallback;
- schema migrations that cannot invent positive claims;
- consolidated post-run assurance.

Still dependent on a suitable live Docker environment:

1. collect a real Docker AI Governance MCP `tool_invocation` + `tool_execution` pair from the DHI live flow;
2. obtain stronger run-to-audit correlation where the available Docker event model supports it;
3. observe a real evaluation → approval/deny → execution chain;
4. execute the direct-MCP bypass probe against the locally installed `sbx` release;
5. verify provider-side token/session invalidation only where a provider exposes a trustworthy postcondition;
6. add a genuinely interoperable transparency-log publication path rather than a cosmetic Rekor claim.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) and [`docs/UPSTREAM_FEEDBACK.md`](docs/UPSTREAM_FEEDBACK.md).

---

## License

Apache-2.0 for this repository's code. Agent Baseline materials remain under their upstream licenses and ownership; authoritative control requirements are not vendored here.
