# Claims Boundary

This project is intentionally strict about the difference between **a useful signal**, **verified evidence**, **artifact trust**, **external trust** and **a causal conclusion**.

A result that refuses to overstate what was observed is considered more correct than a broader green result built from assumptions.

---

## 1. What a control result means

A `PASS` means the **specific implemented evaluator** collected enough evidence for the narrowly defined check it owns during that run.

It does **not** mean:

- Agent Baseline certification;
- official Docker conformance;
- complete satisfaction of every clause in a broader upstream control;
- proof that the same result holds for another agent, environment or future run.

`PARTIAL`, `MANUAL` and `ERROR` are deliberate first-class states. Missing or weak evidence never silently degrades to `PASS`.

---

## 2. Product presence is not enforcement evidence

The following shortcuts are forbidden:

```text
Docker Sandbox exists      -> isolation solved
MCP Gateway exists         -> authorization solved
Cedar policy exists        -> runtime enforcement proven
Audit files exist          -> complete attribution proven
Docker Scout installed     -> image policy satisfied
```

The project must preserve the state, decision, action or postcondition required by the evaluator.

Static policy analysis is **policy evidence**, not runtime-enforcement evidence unless the relevant runtime decision is actually observed.

---

## 3. Artifact existence is not artifact trust

The trusted-artifact layer deliberately rejects shortcuts such as:

```text
OCI archive exists         -> artifact trusted
SBOM exists                -> supply-chain control solved
provenance exists          -> build trusted
non-root user configured   -> image safe
Scout command succeeded    -> policy passed
```

The project verifies the OCI graph and checks relevant attestation subject bindings. An attestation is useful only when it can be tied to the artifact subject it is supposed to describe.

---

## 4. SBOM is not a security guarantee

An SBOM describes software components according to the produced statement. Its existence does not prove:

- absence of vulnerabilities;
- completeness of every runtime dependency;
- safe configuration;
- safe application behavior;
- correctness of the source code.

Therefore:

```text
SBOM present != artifact secure
```

---

## 5. Provenance is not source-code correctness

A verified provenance statement can provide evidence about how a subject was built and bind that statement to an artifact digest.

It does not prove:

- the source code was correct;
- the build instructions were safe;
- the dependencies were non-malicious;
- the resulting application behaves securely at runtime.

Therefore:

```text
provenance verified != code correct
```

---

## 6. Docker Scout pass is scoped policy evidence

Docker Scout integration can be configured as:

- `off`;
- `observe`;
- `gate`.

A passing Scout result means the evaluated artifact satisfied the configured/evaluated policy boundary for that run.

It does **not** mean:

- vulnerability-free;
- future vulnerability-free;
- Docker certification;
- production authorization;
- compliance certification.

`observe` deliberately collects evidence without making Scout a hard disposition gate. `gate` is only appropriate when the PoC explicitly defines Scout success as mandatory.

---

## 7. Agent-to-artifact lineage is not application correctness

The lineage statement binds recorded agent execution state to the post-agent workspace digest and trusted artifact digest.

Successful lineage verification can show that:

- the workspace still matches the state recorded after the agent run;
- the trusted artifact still matches the artifact digest recorded by the trusted-artifact layer;
- the lineage statement binds those subjects.

It does not prove:

- the agent made the correct change;
- the code is secure;
- the container behaves safely at runtime;
- every input to the build was externally trustworthy.

Therefore:

```text
lineage verified != workload safe
```

---

## 8. Internal integrity is not an external trust anchor

The assessment bundle uses:

1. SHA-256 manifests;
2. a hash-linked NDJSON trace;
3. trace-head/event-count anchors in `assessment.json`.

These detect ordinary post-run modification relative to the recorded bundle.

They do not prevent an actor able to rewrite every local anchor from constructing a new internally self-consistent bundle.

The correct claim is **tamper-evident relative to the available anchors**, not tamper-proof.

---

## 9. Evidence integrity is not source completeness

A valid manifest and trace prove consistency of evidence that entered the pipeline.

They cannot prove that every relevant source event was emitted or ingested.

```text
hash chain verifies != telemetry was complete
```

Completeness requires a separate independently trustworthy reconciliation source where that claim matters.

---

## 10. A valid signature is not signer identity

The project signs exact artifacts with Ed25519 and verifies them using a supplied public key.

Successful verification proves possession of the corresponding private key for the exact signed subject.

It does not by itself establish:

- human identity;
- organizational identity;
- key custody quality;
- key freshness or revocation state.

Those claims require an external identity/trust-distribution mechanism.

---

## 11. Release provenance and local artifact signatures are different trust mechanisms

Customer evidence/handoff artifacts use the project’s local Ed25519 trust material.

Project release artifacts use GitHub Artifact Attestations / Sigstore-backed SLSA provenance from the release workflow.

These mechanisms answer different questions:

```text
local Ed25519 signature
  = does this exact customer artifact verify against this supplied key?

GitHub release attestation
  = does this downloadable release artifact verify as produced by the repository/workflow provenance recorded by GitHub?
```

Neither mechanism should be described as broader than the identity/trust boundary it actually verifies.

---

## 12. Response command success is not a verified response postcondition

A successful stop command return code is insufficient evidence of containment. The live response path verifies the named sandbox reached the expected stopped state.

Likewise, removing a local credential binding proves only local removal from that governance surface.

```text
binding removed != upstream provider token revoked
```

Provider-side revocation is claimed only if a trustworthy provider postcondition is actually verified.

---

## 13. MCP approval is not automatically separation of duties

An approval/confirmation policy construct can be useful policy evidence. It is not automatically proof of independent administrator approval, step-up authentication or separation of duties.

Those stronger claims remain non-green until direct evidence exists.

---

## 14. Customer Decision Brief is not production approval

The decision layer returns:

- `BLOCKED`;
- `CONDITIONAL`;
- `EVIDENCE_READY`;
- `DRY_RUN`.

`EVIDENCE_READY` means the configured evidence requirements for the PoC run were satisfied.

It does not mean:

- production approval;
- compliance approval;
- official Docker certification;
- organizational risk acceptance;
- that the artifact is vulnerability-free.

The final deployment/acceptance authority remains external to this project.

---

## 15. Customer Trust Handoff is not automatically externally trusted

A Customer Trust Handoff can be internally verified, privacy-minimized and signed.

That establishes transport integrity/authenticity relative to the supplied trust material.

It does not automatically establish that the public verification key belongs to a particular company or trusted authority.

For higher-assurance deployments, the handoff digest/public key should be distributed or anchored through an independent channel.

---

## 16. Governance Delta is not a causal statement

Governance Delta answers:

> **What changed between two independently verified assessment bundles?**

It does not answer why the change happened.

A control improvement after a governance change is not, by itself, proof that the governance change caused the improvement.

---

## 17. Controlled Experiment `ELIGIBLE` is not proof of causality

The Controlled Experiment Protocol checks whether required **measured** invariants match while the declared governance treatment differs.

`ELIGIBLE` means only that the measured prerequisites for bounded causal discussion are present.

It does not eliminate unmeasured confounders, nondeterminism or source incompleteness.

---

## 18. Dry-run evidence is never live evidence

Dry-run mode validates orchestration, schemas, packaging, signing and fail-closed semantics without mutating Docker resources.

A dry run cannot claim:

- live sandbox isolation;
- live network enforcement;
- a real OCI artifact trust result;
- live SBOM/provenance subject binding;
- live Docker Scout enforcement;
- agent-to-artifact lineage;
- successful containment;
- provider credential revocation;
- Docker AI Governance runtime activity.

CI explicitly checks these boundaries.

---

## Summary

```text
product presence          != observed enforcement
OCI archive exists        != trusted artifact
SBOM present              != secure artifact
provenance verified       != code correct
Scout pass                != vulnerability-free / certified
lineage verified          != workload safe
internal consistency      != external trust
signed artifact           != signer identity
recorded evidence         != source completeness
command success           != verified postcondition
local credential removal  != provider revocation
EVIDENCE_READY            != production approval
before/after delta        != causality
experiment eligibility    != causal proof
dry run                    != live evidence
```

These distinctions are core implementation contracts, not disclaimers added after the fact.
