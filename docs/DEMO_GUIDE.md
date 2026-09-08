# Customer Demo Guide

This guide is the shortest path for showing the project to a technical stakeholder without turning the session into a code tour.

The demo is designed around one question:

> **Can we move from an AI coding-agent governance claim all the way to a container artifact and customer handoff that another person can verify?**

## Recommended format

- **2 minutes** — problem and architecture;
- **4 minutes** — Customer Trust Flow;
- **2 minutes** — inspect trust evidence and decision;
- **2 minutes** — claims boundary and discussion.

The live path is preferable when Docker Sandboxes and Buildx prerequisites are available. The dry-run path is intentionally non-destructive and must never claim live containment, artifact lineage or runtime enforcement.

---

## 1. Open with the problem

Start from the repository home rather than the code.

Use this framing:

> An enterprise adopting coding agents needs more than “the agent is sandboxed”. It needs to know what the agent actually ran, what governance evidence was observed, what artifact came out of that workspace, whether SBOM/provenance bind to the artifact, whether policy checks passed, and whether a reviewer can verify the whole chain independently.

Then point out two deliberate design choices:

- there is no synthetic security score;
- unsupported claims remain non-green.

---

## 2. Run the safe trust-flow path first

Install from source:

```bash
make install
```

Then run the complete non-mutating trust lifecycle:

```bash
make customer-trust-dry-run
```

The target creates a local demo signing key only when one does not already exist, then exercises the full orchestration in dry-run mode.

What this demonstrates:

- assessment, assurance, trusted-artifact and handoff orchestration are wired together;
- the handoff can be built, signed and independently verified;
- privacy checks remain active;
- dry-run cannot create agent-to-artifact lineage;
- dry-run cannot claim live Docker containment or Scout enforcement.

What it does **not** demonstrate:

- live Docker Sandbox isolation;
- live network enforcement;
- a real Buildx OCI artifact;
- real SBOM/provenance subject binding;
- a live Docker Scout result;
- live MCP execution or provider-side revocation.

This fail-closed behavior is also exercised by the dedicated `customer-trust` CI workflow.

---

## 3. Run the live Customer Trust Flow

Before a live customer-facing run:

```bash
make baseline-sync
make signing-keygen
make baseline-lock-verify
make baseline-lock-sign
make baseline-lock-verify-signature
```

Then use the default observation mode:

```bash
make customer-trust SCOUT_MODE=observe
```

Equivalent installed CLI:

```bash
abl-trust --scout-mode observe
```

For MCP-focused environments:

```bash
make customer-trust-mcp SCOUT_MODE=observe
```

The live lifecycle is:

```text
readiness + signed baseline lock
  ↓
unique Docker Sandbox + real coding task
  ↓
Agent Baseline assessment + assurance
  ↓
agent-modified workspace
  ↓
Docker Buildx OCI artifact
  ├─ SBOM
  └─ provenance
  ↓
OCI graph + attestation verification
  ↓
optional Docker Scout policy evidence
  ↓
agent → workspace → artifact lineage
  ↓
customer decision brief
  ↓
SARIF + signed customer trust handoff
```

The important result is not “how many controls are green”. The important result is whether the evidence chain is internally consistent, independently verifiable and explicit about what remains unproven.

---

## 4. Explain Docker Scout modes

The project intentionally separates observation from gating:

```text
off      Scout is excluded from the decision boundary
observe  Scout evidence is collected but does not hard-block the disposition
gate     Scout must pass before EVIDENCE_READY is possible
```

For a first manager demo, prefer:

```bash
make customer-trust SCOUT_MODE=observe
```

This lets you show the integration without making the entire demonstration depend on one local Scout policy configuration.

Use `gate` when the PoC success criteria explicitly require Docker Scout as a hard condition.

---

## 5. Show four artifacts, not forty

### A. Customer Trust Flow HTML

Open:

```text
reports/<run-id>.trust/customer-trust-flow.html
```

Use it to explain the complete chain from agent execution to signed handoff.

### B. Customer Decision Brief

Open:

```text
reports/<run-id>.trust/customer-decision.portable.html
```

Discuss the disposition:

- `BLOCKED`;
- `CONDITIONAL`;
- `EVIDENCE_READY`;
- `DRY_RUN`.

Stress that `EVIDENCE_READY` means the configured PoC evidence boundary was satisfied — not production approval or Docker certification.

### C. Trusted Artifact + lineage

Open:

```text
reports/<run-id>.trust/trusted-artifact.portable.json
reports/<run-id>.trust/agent-artifact-lineage.json
```

Explain that the project verifies:

- the OCI graph;
- SBOM/provenance presence **and subject binding**;
- the artifact digest;
- that the post-agent workspace digest matches the workspace used for lineage;
- that the artifact did not change after the trust statement.

### D. Final handoff

The final file is:

```text
reports/<run-id>.customer-trust-handoff.zip
```

Verify it independently:

```bash
make trust-handoff-verify
```

or:

```bash
python -m agent_baseline_lab.trust_handoff \
  reports/<run-id>.customer-trust-handoff.zip
```

The verifier checks the handoff manifest, member digests/sizes, nested customer evidence pack, nested signatures, private-key exclusion and lineage signature where present.

---

## 6. Show the developer/security integration

The flow also produces SARIF:

```text
reports/<run-id>.trust/agent-governance.sarif
```

This is useful to explain that the pattern can feed existing security tooling rather than requiring a custom dashboard.

---

## 7. Optional before/after story

If the discussion moves from “is this run reviewable?” to “did governance change anything?”, switch to the comparative path.

```bash
make governance-delta \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

Then:

```bash
make experiment-protocol \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

Explain the distinction:

```text
Governance Delta
  = what changed?

Controlled Experiment Protocol
  = were the measured prerequisites for causal discussion present?
```

Do not mix this with the single-run Customer Trust decision; they answer different questions.

---

## Optional Docker MCP / AI Governance path

When the relevant Docker capabilities are available:

```bash
make mcp-register-dhi
make customer-trust-mcp SCOUT_MODE=observe
```

Use this path to discuss:

- controlled MCP registration;
- Cedar policy posture;
- direct-MCP bypass versus governed tool paths;
- optional AI Governance audit evidence;
- why static policy presence is not the same as observed enforcement.

The community path remains useful without licensed AI Governance signals.

---

## Questions the demo should invite

A strong technical review should naturally lead to questions such as:

- Which controls should be locally observed versus centrally enforced?
- Should Scout be `observe` or `gate` for this customer cohort?
- Which identifiers should correlate developer request, agent run, MCP decision and resulting image?
- Which artifact evidence needs external organizational identity rather than a local key?
- Which policy or base-image changes should force re-validation?
- Which parts of this PoC could become a reusable enablement kit for many customers?

---

## Claims boundary to state explicitly

The project does not claim:

- Agent Baseline certification;
- official Docker conformance;
- that an SBOM proves an artifact is secure;
- that provenance proves source code is correct;
- that Scout passing means vulnerability-free;
- that lineage proves runtime behavior is safe;
- that a valid Ed25519 signature proves organizational identity;
- that a before/after improvement proves causality;
- provider-side revocation without a verified provider postcondition.

That restraint is part of the architecture.
