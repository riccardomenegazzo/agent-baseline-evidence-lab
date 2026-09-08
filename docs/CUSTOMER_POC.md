# Customer PoC: governed AI coding agent to trusted container artifact

## Executive scenario

A platform engineering organization wants to make AI coding agents available to developers while preserving a defensible software-supply-chain and governance boundary.

Security and architecture teams need evidence-backed answers to seven questions:

1. **What agent and execution environment were used?**
2. **What could the agent reach and do?**
3. **Which governance decisions were actually observed?**
4. **What exact workspace state did the agent leave behind?**
5. **What exact OCI artifact was built from that state, and do its SBOM/provenance attestations bind to the runnable image?**
6. **Can another reviewer verify the lineage, policy evidence and final handoff without trusting screenshots or the originating workstation?**
7. **If governance changes, can two verified runs be compared without pretending an uncontrolled before/after pair proves causality?**

This PoC uses the Agent Baseline v1.0-draft as a governance vocabulary and Docker Sandboxes, Docker Buildx and optional Docker Scout as the main Docker surfaces.

> Community reference PoC. It does not provide Agent Baseline certification, compliance certification, production authorization or official Docker conformance.

---

## PoC hypothesis

A coding-agent workflow becomes materially more reviewable when the lifecycle is treated as one evidence chain:

```text
agent task
  ↓
governed execution
  ↓
run-scoped assessment evidence
  ↓
agent-modified workspace
  ↓
OCI artifact + SBOM + provenance
  ↓
artifact verification + policy evidence
  ↓
agent-to-artifact lineage
  ↓
explicit customer decision
  ↓
signed portable handoff
```

The PoC is successful when it demonstrates those relationships **without converting product presence, missing telemetry or artifact metadata presence into stronger claims than the evidence supports**.

---

# Scope

## Community path

- Docker Sandbox runtime and policy observations where available;
- safe host-filesystem canary checks;
- network policy decision checks;
- Docker MCP registration/policy posture;
- workspace validation;
- Agent Baseline assessment;
- hash-chained trace and evidence manifest;
- run attestation and Ed25519 authentication;
- disposable response exercise;
- post-run assurance;
- Docker Buildx OCI artifact creation;
- SBOM and provenance attestation generation;
- OCI graph, descriptor and attestation verification;
- portable trusted-artifact statement;
- agent → workspace → artifact lineage;
- customer decision brief;
- SARIF 2.1.0 export;
- signed Customer Trust Handoff;
- Governance Delta;
- Controlled Experiment Protocol.

## Optional environment-dependent path

When the required Docker capabilities, authentication and licenses are available:

- Docker AI Governance local audit ingestion;
- observed MCP `tool_invocation` / `tool_execution` evidence;
- stronger audit correlation;
- environment-specific governance decision chains;
- Docker Scout policy evidence or hard gating according to PoC success criteria.

The optional path is an extension, not a prerequisite for understanding the core reference architecture.

---

# Out of scope

The PoC does not attempt to prove:

- model correctness or safety for every prompt;
- source-telemetry completeness for events that were never emitted;
- organization-wide policy rollout from one workstation;
- upstream provider credential revocation without a trustworthy provider-side postcondition;
- human/organization identity from possession of a local signing key alone;
- vulnerability-free status from an SBOM or Scout pass;
- source-code correctness from provenance;
- runtime application safety from OCI graph integrity;
- causality from a simple before/after status change.

---

# Success criteria

Success criteria distinguish **evidence quality**, **governance outcome**, **artifact trust** and **decision outcome**. The PoC does not need every Agent Baseline control to become `PASS`; precise `PARTIAL`, `MANUAL` or `FAIL` results can still demonstrate that the evidence model behaves correctly.

| ID | Success criterion | Evidence source | Acceptance condition |
|---|---|---|---|
| S1 | Agent has stable identity, owners, purpose and risk context | assessment declaration | required declared fields are present and evidenced |
| S2 | Run is bound to a unique sandbox identity | execution capsule | sandbox identity is preserved across run/response artifacts |
| S3 | Host-only canary is not visible inside the target sandbox | `sbx exec` probe | live postcondition observed, otherwise explicitly non-green |
| S4 | Required network decisions are checked against the named sandbox | `sbx policy check network` | expected allow/deny decisions are evidenced |
| S5 | MCP registration identity is distinguished from generic MCP presence | registration inventory | expected registration name/endpoint can be reconciled when available |
| S6 | MCP policy posture is not mislabeled as runtime enforcement | Cedar analysis | static conclusions are explicitly labelled policy evidence |
| S7 | Agent-modified workspace is validated | validation hooks | configured validation commands execute against the disposable workspace |
| S8 | Assessment evidence is integrity-manifested | `manifest.sha256.json` | independent digest verification succeeds |
| S9 | Normalized trace is hash-linked and anchored | trace + assessment | linkage, event count and head anchor verify |
| S10 | Run attestation binds to the evidence subject | attestation verifier | subject digest recomputes successfully |
| S11 | Positive response claims require observed postconditions | response artifact | dry-run remains negative; live claims require verified state |
| S12 | Portable evidence excludes private signing keys and host path leakage | portable-pack verifier | privacy/trust-boundary checks pass |
| S13 | OCI artifact is not accepted by existence alone | trusted-artifact verifier | OCI graph/descriptor verification succeeds |
| S14 | SBOM and provenance are subject-bound | OCI attestation verification | expected statements bind to the runnable image digest |
| S15 | Artifact digest is preserved as a stable trust subject | trusted-artifact statement | OCI archive digest is recorded and portable trust evidence verifies |
| S16 | Docker Scout semantics are explicit | Scout result | `off`, `observe` or `gate` behavior matches configured PoC boundary |
| S17 | Agent output state is cryptographically linked to artifact state | lineage statement | session workspace digest and artifact digest verify without mutation |
| S18 | Customer disposition is evidence-derived | decision brief | output is `BLOCKED`, `CONDITIONAL`, `EVIDENCE_READY` or `DRY_RUN` with reasons |
| S19 | Security findings are exportable to existing tooling | SARIF | SARIF 2.1.0 artifact is produced and references run evidence |
| S20 | Final handoff is portable and independently verifiable | trust-handoff verifier | manifest, nested pack/signatures and private-key exclusion verify |
| S21 | Final handoff authenticity is bound to the local verification key | Ed25519 | exact ZIP signature verifies against the public key |
| S22 | Two verified runs can be compared without a synthetic score | Governance Delta | delta recomputes and classifies transitions explicitly |
| S23 | Causal discussion is gated by measured invariants | Controlled Experiment Protocol | explicit eligibility outcome with reasons |

---

# Recommended PoC design

## Phase A — establish the fail-closed contract

Install and run the non-mutating Customer Trust Flow:

```bash
make install
make customer-trust-dry-run
```

This should prove orchestration and packaging mechanics while keeping live-only claims false.

Expected dry-run boundaries include:

- no live artifact lineage;
- no live containment claim;
- no runtime Scout enforcement claim;
- no provider revocation claim;
- signed and verifiable handoff mechanics may still execute.

## Phase B — prepare a live baseline

Before a customer-facing run:

```bash
make baseline-sync
make signing-keygen
make baseline-lock-verify
make baseline-lock-sign
make baseline-lock-verify-signature
```

This establishes a verified and signed control-source lock plus local signing material.

## Phase C — execute the live Customer Trust Flow

Start with observation semantics:

```bash
make customer-trust SCOUT_MODE=observe
```

or use the installed command:

```bash
abl-trust --scout-mode observe
```

This executes the complete single-run lifecycle from agent task through artifact and signed handoff.

If the customer success criteria require Docker Scout to be a hard policy condition:

```bash
make customer-trust SCOUT_MODE=gate
```

Do not use `gate` merely to make the PoC look stricter; use it only when Scout policy is explicitly part of the agreed decision boundary.

## Phase D — review the artifact trust chain

Review:

```text
reports/<run-id>.trust/trusted-artifact.portable.json
reports/<run-id>.trust/agent-artifact-lineage.json
reports/<run-id>.trust/customer-decision.portable.html
reports/<run-id>.customer-trust-handoff.zip
```

Then verify the final handoff:

```bash
make trust-handoff-verify
```

The review should answer:

- which image digest is the trust subject;
- whether OCI graph integrity verified;
- whether SBOM/provenance subject binding verified;
- whether Scout was disabled, observed or gated;
- whether lineage was actually created and verified;
- why the customer decision reached its disposition.

## Phase E — bounded governance treatment

If the customer wants a before/after experiment, change one bounded governance treatment while preserving measured invariants as far as possible.

Examples:

- network allow/deny policy;
- MCP registration/profile;
- Cedar policy declaration;
- capability-profile change;
- agreed Scout/base-image policy change.

Do not simultaneously change the task, initial workspace, agent identity and treatment if the goal is to discuss treatment effect.

## Phase F — measure the delta

```bash
make governance-delta \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

Review control improvements/regressions, evidence gains/losses, evaluator recovery/errors, scope changes and unchanged results.

## Phase G — gate causal interpretation

```bash
make experiment-protocol \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

Interpretation:

- `ELIGIBLE` — required measured invariants match and treatment differs;
- `NOT_ELIGIBLE` — an invariant differs or treatment is unchanged;
- `INSUFFICIENT_EVIDENCE` — a required invariant cannot be established.

Even `ELIGIBLE` does not prove causality.

---

# Deliverables

A completed single-run Customer Trust PoC should leave the customer with:

1. machine-readable assessment JSON;
2. human-readable assessment HTML;
3. verified evidence bundle;
4. run attestation and signature;
5. assurance summary;
6. response evidence where a live response exercise executed;
7. portable customer evidence pack;
8. trusted-artifact statement;
9. agent-to-artifact lineage statement where live artifact verification succeeded;
10. customer decision JSON/HTML;
11. SARIF export;
12. signed, independently verifiable Customer Trust Handoff.

For comparative work, add:

13. Governance Delta;
14. Controlled Experiment statement;
15. signed comparison handoff.

---

# Ten-minute stakeholder path

1. Explain the problem and claims boundary.
2. Show `make customer-trust-dry-run` or live `make customer-trust SCOUT_MODE=observe`.
3. Open the Customer Trust Flow HTML.
4. Open the Trusted Artifact and lineage statements.
5. Show the Customer Decision Brief.
6. Verify the final handoff independently.
7. If useful, finish with Governance Delta / Controlled Experiment as the before/after extension.

See [`DEMO_GUIDE.md`](DEMO_GUIDE.md) for the concise talk track.

---

# Decision questions after the PoC

The PoC should end with architecture decisions, not only demo output:

- Which governance controls must be centrally enforced versus locally observed?
- Which supply-chain checks should be informational versus release-blocking?
- Should Docker Scout run in `observe` or `gate` for each customer cohort?
- Which base images are approved, and who owns policy updates?
- Which identifiers can correlate request, agent run, MCP action, policy decision and image digest?
- Which evidence requires organizational/keyless identity rather than a local Ed25519 key?
- What artifact or policy change should trigger mandatory re-validation?
- Which evidence should be retained and for how long?
- Which parts of this reference PoC can become reusable workshops, templates or enablement kits?

---

# PoC completion rule

The PoC is **not** complete because every control is green or because Scout reports no blocker.

It is complete when:

- agreed scenarios executed;
- every automated conclusion has evidence;
- missing evidence remains visible;
- the assessment bundle verifies;
- the trusted artifact verifies according to the agreed boundary;
- lineage verifies when claimed;
- the decision can be explained from evidence;
- the customer handoff independently verifies;
- the customer understands what the evidence does and does not prove;
- next architecture decisions are explicit.
