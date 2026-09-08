# Executive Overview

## What problem does this project address?

AI coding agents can modify code, invoke tools, reach networks and create software artifacts. Enterprise teams therefore need more than a statement that an agent is "sandboxed" or that a policy exists: they need evidence showing what was configured, what was actually observed, what could not be proven, and whether the evidence still verifies after it leaves the originating machine.

**Agent Baseline Evidence Lab** is a community reference PoC for that problem.

It uses the Agent Baseline v1.0-draft as a control vocabulary and Docker Sandboxes as the primary execution surface. The project converts governance requirements into repeatable checks, evidence artifacts and explicit claims boundaries.

> Community project. It is not an official Docker or Agent Baseline product, certification, or conformance program.

## The core idea

Instead of producing a single security score, each run answers a narrower question:

> **For this agent, in this environment, during this run: what can we actually prove?**

A run can combine:

- declared agent identity, ownership, purpose and access intent;
- Docker Sandbox runtime and policy observations;
- bounded adversarial scenarios;
- Docker MCP Cedar-policy analysis;
- optional Docker AI Governance audit metadata;
- validation of the agent-modified workspace;
- a hash-chained normalized trace;
- a SHA-256 evidence manifest;
- run attestation and optional Ed25519 signatures;
- response-drill evidence and portable customer handoffs.

Unsupported claims remain visible as `PARTIAL`, `MANUAL`, `N/A` or `ERROR` rather than being converted into a green result.

## What a customer can demonstrate

A representative PoC can show that a team can:

1. run a real coding task in a uniquely identified Docker Sandbox;
2. test selected runtime and policy boundaries without destructive probes;
3. evaluate the implementation against the 35 draft Agent Baseline controls;
4. preserve machine-readable evidence for every automated conclusion;
5. independently verify bundle integrity and trace linkage;
6. perform a disposable containment / credential-binding response exercise;
7. package evidence for offline review without private signing keys or local path leakage;
8. compare two verified runs control-by-control without inventing a security score;
9. determine whether a before/after pair is sufficiently controlled for **bounded causal interpretation**.

The last point is intentionally strict. The Controlled Experiment Protocol returns one of:

- `ELIGIBLE` — required measured invariants match and the governance treatment differs;
- `NOT_ELIGIBLE` — a required invariant differs, or there is no treatment change;
- `INSUFFICIENT_EVIDENCE` — a required invariant cannot be established.

`ELIGIBLE` is **not** a proof of causality. It only establishes that the measured prerequisites for a controlled comparison are present.

## Why the evidence model matters

The project separates four evidence classes:

| Evidence class | Meaning |
|---|---|
| Declared | configuration and intended state |
| Observed | runtime state, decisions and postconditions actually collected |
| Linked | artifacts correlated by stable identifiers or cryptographic digests |
| Externally anchored | evidence authenticated against material outside the artifact being verified |

This prevents common shortcuts such as treating product presence as enforcement, a successful command return code as a verified postcondition, or a valid signature as proof of signer identity.

## Customer-facing flow

```text
coding task
   ↓
Docker Sandbox
   ↓
Agent Baseline assessment
   ↓
verifiable evidence bundle
   ↓
response + assurance
   ↓
portable signed handoff
   ↓
optional before/after delta
   ↓
controlled-experiment eligibility
```

## What makes the PoC reusable

The repository is designed as a repeatable technical-enablement asset rather than a one-off demo:

- configuration-driven assessment;
- executable success criteria;
- offline-safe and live paths;
- machine-readable JSON plus human-readable HTML;
- deterministic verification commands;
- CI regression tests for false-positive claims and evidence tampering;
- downloadable wheel and source releases with SHA-256 checksums and a release manifest;
- explicit separation between community-accessible paths and optional licensed Docker AI Governance evidence.

## Five-minute review path

For a non-destructive overview:

```bash
make install
make golden-demo-dry-run
```

Then inspect the generated summary and the project documentation:

- [`CUSTOMER_POC.md`](CUSTOMER_POC.md) — customer scenario and measurable success criteria;
- [`DEMO_GUIDE.md`](DEMO_GUIDE.md) — concise walkthrough;
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — technical architecture;
- [`GOVERNANCE_DELTA.md`](GOVERNANCE_DELTA.md) — verified before/after comparison;
- [`CONTROLLED_EXPERIMENT.md`](CONTROLLED_EXPERIMENT.md) — causal-eligibility boundary;
- [`CLAIMS_BOUNDARY.md`](CLAIMS_BOUNDARY.md) — what the project deliberately does not claim.

## Current maturity

The project is an implementation and assurance lab, not a finished enterprise governance product. Its value is the reference pattern: translating a governance requirement into an observable test, preserving the evidence, and refusing to claim more than the available evidence supports.
