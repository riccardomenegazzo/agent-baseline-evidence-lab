# Evidence Model

An assessment result is useful only when another reviewer can answer more than “is it green?”. The project is designed so a reviewer can ask:

1. **What did we expect?**
2. **What was declared?**
3. **What was actually observed?**
4. **Which control/check used that evidence?**
5. **Can we detect if the evidence changed afterwards?**
6. **What external trust, if any, authenticates the evidence?**
7. **What remains unproven?**

---

## Four evidence classes

### 1. Declared evidence

Configuration or design intent supplied to the assessment.

Examples:

- agent ID and owners;
- intended access/resources/actions;
- configured network allow/deny targets;
- selected MCP registrations;
- declared capability profile;
- policy files selected for analysis.

Declared evidence is useful, but it does not prove effective runtime state.

### 2. Observed evidence

State, decisions or postconditions actually collected during the run.

Examples:

- Docker Sandbox inventory;
- `sbx policy check` results;
- host-canary visibility result;
- workspace before/after hashes;
- validation command return codes;
- finalized Docker AI Governance events when available;
- verified stopped-state observation after a response exercise.

Observed evidence is stronger than declaration for runtime claims, but its completeness still depends on the source.

### 3. Linked evidence

Artifacts tied together through stable identifiers or cryptographic digests.

Examples:

- assessment bundle manifest;
- trace head anchored in the assessment;
- execution capsule imported through a verified manifest;
- response-link binding assessment and response evidence;
- incident bundle containing digests of referenced artifacts;
- Governance Delta anchored to before/after manifest digests.

Linked evidence establishes relationships between known artifacts. It does not automatically create external trust.

### 4. Externally anchored evidence

Evidence authenticated against material held outside the artifact being verified.

Examples:

- expected manifest / trace-head digest retained independently;
- Ed25519 signature verified using an independently trusted public key;
- a future interoperable transparency-log or identity-bound signature path.

This class is what can detect attacks that rewrite all local anchors consistently, assuming the external anchor itself is trustworthy.

---

## Status semantics

| Status | Meaning |
|---|---|
| `PASS` | The evaluator collected enough evidence for the narrowly implemented check it owns. |
| `FAIL` | Observed/declared state contradicts the implemented check or a required condition is absent. |
| `PARTIAL` | Useful evidence exists, but the broader upstream requirement includes unproven dimensions. |
| `MANUAL` | The project cannot currently collect sufficient automated evidence for the requirement. |
| `N/A` | The control was explicitly scoped out with justification. |
| `ERROR` | The evaluator failed; this never degrades to `PASS`. |

A `PASS` is not an Agent Baseline certification or a statement that every clause of the upstream control is satisfied.

---

## Run-scoped evidence

Automated evaluators emit run-scoped artifacts below:

```text
evidence/<run-id>/controls/<control-id>/
```

The run also contains:

```text
evidence/<run-id>/assessment.json
evidence/<run-id>/trace/events.ndjson
evidence/<run-id>/manifest.sha256.json
```

`manifest.sha256.json` records the SHA-256 digest and size of collected evidence files.

The normalized NDJSON trace links each event to its predecessor through SHA-256 hashes. The final trace head and event count are anchored in the assessment.

---

## Execution evidence versus assessment evidence

The live agent execution capsule is deliberately separate from the assessment bundle.

```text
agent-runs/<session-id>/
```

captures bounded run metadata such as:

- task digest;
- unique sandbox identity;
- workspace-before digest;
- workspace-after digest;
- changed paths;
- Docker observations;
- execution command metadata.

The assessment verifies the capsule manifest before importing it. This prevents an unverified execution record from silently becoming assessment evidence.

---

## Integrity model

The project uses three local consistency mechanisms:

1. SHA-256 evidence manifest;
2. hash-chained trace;
3. trace-head/event-count anchors in `assessment.json`.

These detect ordinary post-run modification.

The adversarial verifier matrix also demonstrates the limit: an actor able to rewrite the full local bundle can produce a new internally consistent bundle. An independently held digest/signature is required to detect that coordinated rewrite.

Therefore the project uses the term **tamper-evident**, not tamper-proof.

---

## Authenticity model

Selected artifacts can be signed with Ed25519:

- upstream baseline lock;
- run attestation;
- Governance Delta;
- Controlled Experiment statement;
- portable customer pack / comparison pack.

Signature verification proves the exact artifact is valid relative to the supplied public key.

Signer identity is a separate claim. A local public key does not become an organizational identity simply because the signature validates.

---

## Completeness model

Evidence integrity and authenticity cannot prove that the source emitted every relevant event.

The project therefore distinguishes:

```text
integrity      = recorded artifacts were not changed relative to their anchors
authenticity   = an artifact verifies against trusted signing material
completeness   = the relevant source population was fully represented
```

Completeness requires an independent witness/reconciliation source where that claim matters.

---

## Response evidence

Response artifacts require observed postconditions for positive claims.

Examples:

- a sandbox stop command is not enough; stopped state must be verified;
- removing a local credential binding is evidence of local removal only;
- upstream provider revocation is not claimed unless a provider-side postcondition is verified.

Dry-run response artifacts deliberately keep positive containment/revocation claims false.

---

## Before/after evidence

### Governance Delta

Governance Delta compares two independently verified assessment bundles and classifies control transitions.

It answers:

> **What changed in the evidence-backed control results?**

It does not answer why the change occurred.

### Controlled Experiment Protocol

The experiment protocol evaluates whether required measured invariants match and whether a governance treatment differs.

It answers:

> **Is this pair sufficiently controlled, based on the measured evidence, for bounded causal discussion?**

Its `ELIGIBLE` outcome is not a causal proof.

---

## Customer handoff model

Portable packs separate shareable evidence from local/private execution state.

Default handoffs exclude private signing keys and are checked for local path leakage. Comparison handoffs contain both independently verifiable customer packs plus the signed before/after statement.

A portable pack is still a transport artifact. Higher-assurance authenticity requires the pack digest or public key to be trusted through a channel outside the pack itself.

---

## Core rule

When evidence is missing, ambiguous or weaker than the desired claim, the system preserves that uncertainty.

It never converts uncertainty into confidence merely to make the report look better.
