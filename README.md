# Agent Baseline Evidence Lab

[![CI](https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/actions/workflows/ci.yml)

**Turn the Agent Baseline v1.0-draft into reproducible implementation evidence for a real AI coding-agent environment.**

> Community project. Not an official Docker, Sigstore, Snyk, Keycard, or Agent Baseline project. It does **not** issue certifications or claim official conformance.

AI-agent security guidance is easy to describe and hard to prove. This lab asks a narrower question:

> **For this agent, in this environment, during this run: what can we actually prove?**

The project maps the 35 draft Agent Baseline controls to declared state, live Docker Sandboxes probes, Docker MCP governance, optional Docker AI Governance audit records, executable adversarial scenarios, agent-generated artifact checks, incident-response exercises and explicit manual gaps.

The core rule is simple: **product presence is never treated as proof of a control.**

## Five-minute manager path

After installation and Docker Sandboxes authentication:

```bash
make interview-demo
```

The end-to-end community flow is:

```text
real coding task
      │
      ▼
Codex in a unique Docker Sandbox
      │
      ▼
Agent Baseline assessment
      │
      ├── live boundary probes
      ├── adversarial scenarios
      ├── artifact validation
      └── explicit unresolved controls
      │
      ▼
verified assessment bundle
      │
      ▼
disposable response drill
      ├── sandbox-scoped test credential binding
      ├── observe → revoke → verify absence
      └── stop exact sandbox → verify stopped state
      │
      ▼
response evidence
      │
      ▼
assessment SHA-256 + response SHA-256
      │
      ▼
response-link statement + independent verification
```

The orchestration uses the **actual unique sandbox identity returned by that run**, never a hard-coded response target.

For the MCP + Docker AI Governance variant:

```bash
make mcp-register-dhi
make interview-demo-mcp
```

For a zero-mutation orchestration check:

```bash
make interview-demo-dry-run
```

Dry-run mode is required to report live response claims as false and is continuously tested in CI.

## v0.7 assurance layer

v0.7 extends the lab beyond assessment into four connected assurance areas.

### Cryptographic trust

```bash
make trust-keygen
make sign-latest
make verify-latest-signature
```

Evidence can be signed with portable Ed25519 OpenSSH signatures. The verifier can require an externally supplied signer fingerprint, separating **signature validity** from **trust in signer identity**.

Optional public transparency logging is available through Sigstore Rekor:

```bash
make rekor-publish-latest
```

This is an explicit external side effect and is never run automatically. CI exercises only `make rekor-dry-run`.

### MCP governance evidence

```bash
make mcp-runtime-dhi
make mcp-action-chains
```

The lab can now:

- observe a registered MCP server with `sbx mcp inspect`;
- compare its observed identity URL with an expected canonical identity;
- capture OAuth authorization **status and scope metadata only**;
- correlate Docker audit evaluation / approval-or-deny / invocation / execution records by Docker correlation keys;
- statically verify explicit `invokePrimordial` restrictions;
- test the direct-MCP bypass boundary jointly with sandbox network policy.

The DHI and strict reference policies explicitly restrict dynamic gateway expansion via selected primordials including `mcp-add`, `mcp-exec`, `mcp-find`, `mcp-config-set` and `code-mode`.

Direct connections do not become “MCP governed” merely because a gateway policy exists. A positive defense-in-depth claim requires the gateway posture **and** a live network-policy denial for the direct endpoint.

### Observe: drift and unintended actions

Create a known-good behavior profile:

```bash
make drift-baseline-latest
```

Compare a later evidence trace:

```bash
make drift-check-latest
```

The profile can detect differences in observed destinations, MCP tools, event frequencies and resource metrics that exist in the trace. A difference is called **drift**, not maliciousness.

The metadata-only unintended-action detector:

```bash
make unintended-latest
```

flags a credential-like path and source-code path changing in the same agent run without opening or persisting candidate credential contents.

### Respond and preserve

A non-agent fallback can be tested independently:

```bash
make fallback-demo
```

A component quarantine decision can be appended to an evidence-linked registry:

```bash
make quarantine-latest SANDBOX=<component-id>
```

An evidence-preserving incident package can then be built and independently checked:

```bash
make incident-latest
make incident-verify-latest
```

A typical assurance chain is now:

```text
agent run
  ↓
assessment bundle
  ↓
response evidence
  ↓
response-link
  ↓
fallback / quarantine evidence
  ↓
incident bundle
  ↓
incident manifest
  ↓
Ed25519 signature
  ↓
externally pinned fingerprint
  ↓
optional Rekor entry
```

See [`docs/V0.7_TRUST_AND_RESPONSE.md`](docs/V0.7_TRUST_AND_RESPONSE.md) for the exact trust and claims boundaries.

## Evidence, not greenwashing

The lab deliberately refuses shortcuts such as:

- `Docker Sandbox installed → CON-03 PASS`
- `MCP Gateway present → authorization solved`
- `Cedar file exists → enforcement proven`
- `audit logs exist → end-to-end attribution proven`
- `sbx stop returned 0 → containment proven`
- `credential binding removed → provider token revoked`
- `signature verifies → signer identity trusted`
- `hash chain verifies → source telemetry was complete`

Every Agent Baseline control is one of:

`PASS` · `FAIL` · `PARTIAL` · `MANUAL` · `N/A` · `ERROR`

A skipped live test is **never** counted as a pass.

The project distinguishes:

1. **declared evidence** — configuration and design intent;
2. **observed evidence** — runtime state, policy decisions, audit records and postconditions;
3. **linked evidence** — artifacts correlated by cryptographic digest;
4. **externally anchored evidence** — a digest, signature key/fingerprint or transparency record trusted outside the evidence producer boundary;
5. **completeness evidence** — reconciliation against an independent expectation or source-of-record.

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
      Cedar analysis         Scenario runner       Docker audit JSONL
      + MCP runtime          + artifact tests      + correlation
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
                                   ▼
                         response / incident evidence
                                   │
                                   ▼
                           optional signature
                                   │
                                   ▼
                         external fingerprint
                         / optional Rekor log
```

## Quick start

```bash
make install
make preflight
make demo
make verify
make evidence-matrix
```

The offline path remains intentionally useful. Without `sbx`, live controls become `SKIP`/`MANUAL`; structural policy, artifact and evidence-integrity tests still execute.

A real Codex-in-Sandbox task:

```bash
make live-demo
```

The live capsule stores prompt/output digests rather than raw content by default and records workspace hashes before and after execution.

## MCP vertical slice

Register Docker's public DHI MCP endpoint:

```bash
make mcp-register-dhi
```

Then:

```bash
make live-demo-mcp
```

Reference policy: [`policies/mcp/dhi-readonly.cedar`](policies/mcp/dhi-readonly.cedar).

Static Cedar analysis remains design evidence until the relevant organization actually enforces the policy and runtime decisions are observed.

OAuth credential removal is intentionally separate from normal assessment because it mutates host-side credential state.

Contract only:

```bash
make mcp-oauth-dry-run
```

Explicit live operation against a deliberately disposable OAuth authorization:

```bash
make mcp-oauth-revoke MCP_SERVER=<server>
```

A positive claim requires an observed authorized state before removal and an observed unauthorized/absent state afterward.

## Response evidence

Basic sandbox containment:

```bash
make response-drill
```

Stronger disposable binding exercise:

```bash
make response-drill-full
```

Link the verified response artifact to the assessment without modifying either source:

```bash
make response-link
make response-link-verify
```

Removing a Docker sandbox credential binding does **not** claim upstream provider token invalidation.

## Evidence verification matrix

```bash
make evidence-matrix
```

The matrix attacks disposable copies of a verified bundle and keeps four different properties separate:

| Scenario | Internal verification | External original anchor |
|---|---:|---:|
| uncoordinated file alteration | detects | detects |
| trace truncation without anchor rewrite | detects | detects |
| coordinated trace + local-anchor rewrite | may pass | detects |
| source event never emitted | cannot infer it | cannot infer it |

The last case is why the project also supports an independent **completeness witness**. Artifact integrity alone cannot prove an event existed if the event never entered the export.

See [`docs/UPSTREAM_OBS06_TEST_METHOD.md`](docs/UPSTREAM_OBS06_TEST_METHOD.md).

## Tamper evidence and provenance

`abl verify` checks:

1. every manifested file digest;
2. every trace hash-chain link;
3. trace head and event count against assessment anchors.

For an external boundary:

```bash
abl verify evidence/abl-... \
  --expected-manifest-sha256 <sha256> \
  --expected-trace-head <sha256>
```

The existing in-toto-style run attestation remains intentionally unsigned. v0.7 adds a **separate portable signing layer** so the project does not silently change the semantics of older attestation artifacts.

## Docker AI Governance correlation

When local finalized Docker audit JSONL is available, the lab preserves Docker `audit_event_id` and `audit_session_id`, normalizes semantic events and can emit action chains.

A run-scoped reserved `.invalid` hostname can be used as an empirical correlation marker. Correlation strength remains explicit:

- `exact-marker`;
- `single-daemon-session`;
- `ambiguous-multi-session`;
- `pending-finalization`;
- `no-observed-correlation`.

A single daemon session is supporting evidence, not exact task attribution.

## Schema evolution

Inspect an artifact:

```bash
python -m agent_baseline_lab.schema inspect <artifact.json>
```

Migrate a supported legacy artifact:

```bash
python -m agent_baseline_lab.schema migrate <artifact.json> --output <new.json>
```

Migrations are conservative: they may add missing negative/default fields, but must never invent a positive security claim.

## Development and CI

```bash
make install
make test
make lint
make interview-demo-dry-run
```

CI validates:

- Ruff and framework tests;
- sample application tests;
- metadata-only agent execution;
- MCP and OAuth anti-false-claim dry runs;
- response anti-false-claim contracts;
- evidence attack matrix;
- bundle and attestation verification;
- non-agent fallback execution;
- incident preservation and verification;
- real ephemeral Ed25519 signatures;
- signature verification against an externally supplied fingerprint;
- non-publishing Rekor dry-run semantics.

GitHub Actions dependencies are pinned by commit SHA.

## What remains deliberately unclaimed

v0.7 implements the primitives, but these require real external evidence before they can be called verified:

1. a finalized governed Docker AI Governance MCP evaluation + invocation + execution chain;
2. exact correlation of that chain to one real coding-agent task;
3. live OAuth revocation against a deliberately disposable authorization;
4. a deliberately public Rekor entry;
5. a signer fingerprint anchored outside this repository/evidence producer;
6. a clean-machine full PoC run archived as a signed incident/evidence package.

See [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Documentation

- [`docs/INTERVIEW_DEMO.md`](docs/INTERVIEW_DEMO.md) — five-minute technical-manager walkthrough
- [`docs/CUSTOMER_POC.md`](docs/CUSTOMER_POC.md) — reusable customer scenario and success criteria
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — evidence-engine architecture
- [`docs/DOCKER_EVIDENCE_SOURCES.md`](docs/DOCKER_EVIDENCE_SOURCES.md) — Docker evidence boundaries
- [`docs/RUN_ATTESTATION.md`](docs/RUN_ATTESTATION.md) — in-toto-style run statement
- [`docs/RESPONSE_DRILL.md`](docs/RESPONSE_DRILL.md) — containment and scoped binding revocation
- [`docs/V0.7_TRUST_AND_RESPONSE.md`](docs/V0.7_TRUST_AND_RESPONSE.md) — signatures, MCP, drift, incident preservation
- [`docs/UPSTREAM_OBS06_TEST_METHOD.md`](docs/UPSTREAM_OBS06_TEST_METHOD.md) — independent-evidence test method
- [`CHANGELOG.md`](CHANGELOG.md) — release history

## Project status — v0.7.0

This is an implementation lab and customer PoC, not a finished assurance product. Its strongest design property is not the number of checks; it is the refusal to promote design intent, command success or self-consistent local hashes into stronger claims than the evidence supports.

## License

Apache-2.0 for this repository's code. Agent Baseline materials remain under their upstream licenses and ownership; authoritative control requirements are not vendored here.
