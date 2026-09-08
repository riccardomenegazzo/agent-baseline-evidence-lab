# Evidence Model

An evidence result is useful only when another reviewer can answer more than “is it green?”. The project is designed so a reviewer can ask:

1. **What did we expect?**
2. **What was declared?**
3. **What was actually observed?**
4. **Which control or artifact check used that evidence?**
5. **What exact artifact digest is the trust subject?**
6. **Can we detect if the evidence or artifact changed afterwards?**
7. **What external trust, if any, authenticates the result?**
8. **What remains unproven?**

---

# Four evidence classes

## 1. Declared evidence

Configuration or design intent supplied to the assessment.

Examples:

- agent ID and owners;
- intended access/resources/actions;
- configured network allow/deny targets;
- selected MCP registrations;
- declared capability profile;
- policy files selected for analysis;
- configured Docker Scout mode.

Declared evidence is useful but does not prove effective runtime state.

## 2. Observed evidence

State, decisions or postconditions actually collected during the run.

Examples:

- Docker Sandbox inventory;
- `sbx policy check` results;
- host-canary visibility result;
- workspace before/after hashes;
- validation command return codes;
- finalized Docker AI Governance events when available;
- verified stopped-state observation;
- Buildx-produced OCI metadata;
- Docker Scout command result.

Observed evidence is stronger than declaration for runtime claims, but its completeness still depends on the source.

## 3. Linked evidence

Artifacts tied together through stable identifiers or cryptographic digests.

Examples:

- assessment bundle manifest;
- trace head anchored in the assessment;
- execution capsule imported through a verified manifest;
- response link;
- incident artifact digests;
- trusted-artifact OCI archive SHA-256;
- SBOM/provenance subjects bound to the runnable image digest;
- agent session workspace digest bound to artifact lineage;
- Governance Delta anchored to before/after manifest digests.

Linked evidence establishes relationships between known artifacts. It does not automatically create external trust.

## 4. Externally anchored evidence

Evidence authenticated against material held outside the artifact being verified.

Examples:

- expected manifest/trace-head digest retained independently;
- Ed25519 signature verified using a public key trusted through an independent channel;
- GitHub Artifact Attestation verified against repository/workflow identity for downloadable releases;
- future transparency-log or organization-bound signing paths.

This class can detect some attacks that rewrite all local anchors consistently, assuming the external anchor itself is trustworthy.

---

# Status semantics

## Agent Baseline control statuses

| Status | Meaning |
|---|---|
| `PASS` | The evaluator collected enough evidence for the narrowly implemented check it owns. |
| `FAIL` | Observed/declared state contradicts the implemented check or a required condition is absent. |
| `PARTIAL` | Useful evidence exists, but broader dimensions remain unproven. |
| `MANUAL` | The project cannot currently collect sufficient automated evidence. |
| `N/A` | The control was explicitly scoped out with justification. |
| `ERROR` | The evaluator failed; this never degrades to `PASS`. |

## Assurance statuses

| Status | Meaning |
|---|---|
| `PASS` | An integrity/authenticity verification executed and succeeded. |
| `FAIL` | A blocking verification failed. |
| `FINDING` | A non-blocking risk signal requires review. |
| `NOT_RUN` | Optional evidence was unavailable or not applicable. |

## Customer decision statuses

| Status | Meaning |
|---|---|
| `BLOCKED` | A required trust condition failed. |
| `CONDITIONAL` | Useful evidence exists, but the configured decision boundary is not fully satisfied. |
| `EVIDENCE_READY` | Configured PoC evidence requirements are satisfied for this run. |
| `DRY_RUN` | Orchestration was exercised without live trust claims. |

These status families answer different questions and are intentionally not collapsed into one score.

---

# Run-scoped governance evidence

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

The manifest records SHA-256 and size of evidence files. The normalized trace hash-links each event to its predecessor. Final trace head and event count are anchored in the assessment.

---

# Execution evidence versus assessment evidence

The live agent execution capsule is deliberately separate:

```text
agent-runs/<session-id>/
```

It captures bounded metadata such as:

- task digest;
- unique sandbox identity;
- workspace-before digest;
- workspace-after digest;
- changed paths;
- Docker observations;
- execution metadata.

The assessment verifies the capsule manifest before importing it.

---

# Artifact trust evidence

The artifact trust plane introduces a second evidence subject: the container artifact produced from the agent-modified workspace.

Typical trust artifacts include:

```text
reports/<run-id>.trust/
├── trusted-artifact.portable.json
├── trusted-artifact.portable.json.ed25519.json
├── agent-artifact-lineage.json
├── agent-artifact-lineage.json.ed25519.json
├── customer-decision.portable.json
├── customer-decision.portable.html
├── customer-decision.portable.json.ed25519.json
├── agent-governance.sarif
└── customer-trust-flow.html
```

The local trusted-artifact work area may also contain the OCI archive and BuildKit/Scout outputs. Binary OCI layers are not included in the default customer handoff.

## OCI graph integrity

The verifier checks descriptor relationships, digests and sizes rather than trusting archive presence.

## Attestation evidence

SBOM and provenance statements are evaluated as **subject-bound evidence**. Their presence is insufficient when they cannot be tied to the runnable image subject.

## Docker Scout evidence

Scout evidence is explicitly scoped by mode:

```text
off      not part of disposition
observe  collected as evidence, non-blocking
gate     required for EVIDENCE_READY
```

The mode is part of the decision context so a reviewer can distinguish “not evaluated” from “evaluated and passed”.

---

# Agent-to-artifact lineage evidence

The lineage statement links:

1. agent session identity;
2. verified post-agent workspace root digest;
3. trusted OCI artifact digest;
4. trusted-artifact verification state.

Lineage creation fails if the workspace or artifact no longer matches the recorded trust subjects.

This establishes a cryptographic relationship between recorded states. It does not establish application correctness or runtime safety.

---

# Integrity model

The project uses local consistency mechanisms including:

- SHA-256 evidence manifests;
- hash-chained trace;
- trace-head/event-count anchors;
- OCI descriptor digest/size validation;
- trusted-artifact archive digest binding;
- signed portable trust statements;
- handoff manifests over every exported member.

These detect ordinary post-run modification relative to recorded anchors.

An actor able to rewrite every local artifact and every local trust anchor consistently may still create a new internally consistent state. External trust material is needed to detect that class of attack.

Therefore the project uses **tamper-evident**, not tamper-proof.

---

# Authenticity model

Customer/run artifacts can be signed with Ed25519, including:

- baseline lock;
- run attestation;
- Governance Delta;
- Controlled Experiment statement;
- portable customer pack/comparison pack;
- trusted-artifact portable statement;
- agent-artifact lineage;
- customer decision;
- final Customer Trust Handoff.

Verification proves the exact artifact is valid relative to the supplied public key.

Signer identity is a separate claim.

For project releases, GitHub Artifact Attestations provide a different provenance boundary tied to GitHub repository/workflow identity. See [`RELEASE_PROVENANCE.md`](RELEASE_PROVENANCE.md).

---

# Completeness model

Integrity and authenticity cannot prove that every relevant source event was emitted.

```text
integrity      = recorded artifacts were not changed relative to anchors
authenticity   = an artifact verifies against trusted signing/provenance material
completeness   = the relevant source population was fully represented
```

Completeness requires independent reconciliation where that claim matters.

---

# Response evidence

Positive response claims require observed postconditions.

Examples:

- stop command success is insufficient; stopped state must be verified;
- local credential-binding removal proves local removal only;
- upstream provider revocation requires provider-side evidence.

Dry-run response artifacts deliberately keep positive claims false.

---

# Customer handoff evidence

The Customer Trust Handoff separates portable trust evidence from local/private execution state.

The verifier checks:

- safe ZIP member paths;
- duplicate/unmanifested member rejection;
- SHA-256 and size for manifested files;
- nested customer-pack integrity;
- nested signatures where present;
- private-key exclusion;
- OCI binary archive exclusion;
- lineage signature where present.

A signed handoff is still a transport/authenticity artifact relative to the supplied key. Organizational identity remains external.

---

# Before/after evidence

## Governance Delta

Answers:

> **What changed in the evidence-backed control results?**

It does not answer why.

## Controlled Experiment Protocol

Answers:

> **Is this pair sufficiently controlled, based on measured evidence, for bounded causal discussion?**

`ELIGIBLE` is not causal proof.

---

# Core rule

When evidence is missing, ambiguous or weaker than the desired claim, the system preserves that uncertainty.

It never converts uncertainty into confidence merely to make the report, artifact or customer decision look better.
