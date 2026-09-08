# Customer Demo Guide

This guide is the shortest path for showing the project to a technical stakeholder without turning the session into a code tour.

The demo is designed around one question:

> **Can we move from an AI-agent governance claim to evidence that another person can verify?**

## Recommended format

- **2 minutes** — problem and architecture;
- **3 minutes** — run / inspect evidence;
- **2 minutes** — before/after governance comparison;
- **2 minutes** — claims boundary and discussion.

The live path is preferable when Docker Sandboxes prerequisites are available. The dry-run path is intentionally non-destructive and must never claim live containment, revocation or runtime enforcement.

---

## 1. Open with the problem

Start from the repository home rather than the code.

The core message is:

> An enterprise does not only need to know that an AI agent is sandboxed. It needs to know what was observed, which control conclusion came from which evidence, what remains unproven, and whether the evidence can be independently verified.

Point out that the project deliberately avoids a synthetic security score.

---

## 2. Show the safe path first

Install from source:

```bash
make install
```

Then run the non-mutating orchestration check:

```bash
make golden-demo-dry-run
```

What this demonstrates:

- the complete orchestration path can be exercised without creating a live agent run;
- positive response and revocation claims remain false;
- signed and portable handoff mechanics can still be validated;
- the CI enforces those fail-closed semantics.

What it does **not** demonstrate:

- live Docker Sandbox isolation;
- runtime network enforcement;
- live MCP execution;
- actual provider-side credential revocation.

---

## 3. Run the live customer flow

Before a customer-facing live run, synchronize and verify the draft baseline source and establish the local signing key:

```bash
make baseline-sync
make signing-keygen
make baseline-lock-verify
make baseline-lock-sign
make baseline-lock-verify-signature
```

Then run:

```bash
make golden-demo
```

The live lifecycle is expected to:

```text
readiness
  ↓
unique Docker Sandbox + real coding task
  ↓
Agent Baseline assessment
  ↓
immutable evidence bundle
  ↓
response exercise
  ↓
attestation + assurance
  ↓
portable customer evidence pack
```

The important part is not the number of `PASS` controls. The important part is that every automated conclusion has inspectable evidence and unsupported conclusions remain non-green.

---

## 4. Inspect three artifacts, not thirty files

For a short meeting, show only these layers:

### A. Human-readable assessment report

Open the latest HTML report under `reports/`.

Highlight:

- control status;
- explanation;
- evidence references;
- explicit `PARTIAL` / `MANUAL` outcomes.

### B. Evidence manifest

Open the corresponding:

```text
evidence/abl-<run>/manifest.sha256.json
```

Then run:

```bash
make verify
```

Explain that verification checks the evidence file digests and the normalized trace linkage rather than trusting the report presentation.

### C. Assurance summary

Run:

```bash
make assurance-latest
```

Open:

```text
reports/assurance-summary.json
```

The assurance layer distinguishes blocking integrity failures from non-blocking findings and optional evidence that was not available.

---

## 5. Show the before/after model

When two verified runs exist:

```bash
make governance-delta \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

This produces a control-by-control transition statement without a security score.

Then evaluate whether the pair is suitable for bounded causal discussion:

```bash
make experiment-protocol \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

The distinction is important:

```text
Governance Delta
  = what changed?

Controlled Experiment Protocol
  = were the measured prerequisites for causal interpretation present?
```

An improvement in control status is not automatically described as a treatment effect.

---

## 6. Show the handoff

Create the portable comparison pack:

```bash
make comparison-pack \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>

make comparison-pack-verify
```

The handoff contains the before/after customer evidence, governance delta, verification material and public key while excluding the local private signing key.

This is the point where the project becomes useful as a customer-enablement pattern: the reviewer does not need the originating workstation to inspect the evidence package.

---

## Optional Docker MCP / AI Governance path

When the required Docker capabilities and access are available:

```bash
make mcp-register-dhi
make live-demo-mcp
```

Use this path to discuss:

- controlled MCP registration;
- Cedar policy posture;
- direct-MCP bypass versus governed tool paths;
- optional AI Governance audit evidence;
- why static policy presence is not the same as observed enforcement.

Do not make the optional licensed path a prerequisite for understanding the community PoC.

---

## Questions the demo should invite

A strong technical review should naturally lead to questions such as:

- Which controls should be enforced locally and which centrally?
- What identifiers should correlate the developer request, agent run, MCP decision and resulting artifact?
- Which evidence should be signed or externally anchored?
- What changes should invalidate a previous governance assessment?
- When does a before/after comparison become sufficiently controlled to discuss causality?
- Which parts of this pattern could become reusable enablement for multiple customer cohorts?

---

## Claims boundary to state explicitly

The project does not claim:

- Agent Baseline certification;
- official Docker conformance;
- proof that telemetry was complete if an event was never emitted;
- proof of signer identity from a signature alone;
- proof of causality from a before/after status change;
- upstream provider revocation unless an actual provider postcondition is verified.

That restraint is part of the design, not a missing feature.
