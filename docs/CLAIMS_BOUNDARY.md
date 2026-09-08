# Claims Boundary

This project is intentionally strict about the difference between **a useful signal**, **verified evidence**, **external trust** and **a causal conclusion**.

The claims boundary is part of the implementation. A result that refuses to overstate what was observed is considered more correct than a broader green result built from assumptions.

---

## 1. What a control result means

A `PASS` means that the **specific implemented evaluator** collected enough evidence for the narrowly defined check it owns during that run.

It does **not** mean:

- Agent Baseline certification;
- official Docker conformance;
- complete satisfaction of every clause in a broader upstream control;
- proof that the same result holds for another agent, environment or future run.

A `PARTIAL` is often the most accurate result. For example, observing Docker Sandbox host-canary separation and expected network decisions provides useful evidence for part of an isolation control, while other dimensions such as credential delivery, compute, process count, persistence or retained state may remain unproven.

`MANUAL` means the project does not currently possess enough automated evidence for the check. `ERROR` means the evaluator failed. Neither state can silently degrade to `PASS`.

---

## 2. Product presence is not enforcement evidence

The following shortcuts are explicitly forbidden:

```text
Docker Sandbox exists      -> isolation solved
MCP Gateway exists         -> authorization solved
Cedar policy file exists   -> runtime enforcement proven
Audit files exist          -> complete attribution proven
SBOM exists                -> software-supply-chain control solved
```

The project must observe the state, decision, action or postcondition required by the evaluator and preserve the resulting evidence.

Static policy analysis is therefore labelled as **policy evidence**. It is not promoted to runtime-enforcement evidence unless the relevant runtime decision is actually observed.

---

## 3. Internal integrity is not an external trust anchor

The assessment bundle uses:

1. a SHA-256 manifest over evidence files;
2. a hash-linked NDJSON trace;
3. trace-head and event-count anchors in `assessment.json`.

These mechanisms detect ordinary post-run modification relative to the recorded bundle.

They do not make the producer incapable of rewriting all local artifacts consistently.

The adversarial verification matrix intentionally demonstrates that a coordinated producer-side rewrite can remain internally self-consistent when every local anchor is rewritten together. An independently retained digest or trusted external signature can detect that rewrite because it creates a trust boundary outside the rewritten bundle.

The correct claim is therefore **tamper-evident relative to the available anchors**, not tamper-proof.

---

## 4. Evidence integrity is not source completeness

A valid manifest and trace prove consistency of the evidence that entered the pipeline.

They cannot prove that every relevant source event was emitted or ingested.

If an event never enters the evidence pipeline, the exported bundle cannot reconstruct its existence. Source completeness requires a separate witness or reconciliation mechanism with an independently trustworthy source.

This is why:

```text
hash chain verifies != telemetry was complete
```

---

## 5. A valid signature is not signer identity

The project can sign exact artifacts with Ed25519 and verify them with a supplied public key.

Successful verification proves that:

- the signed subject matches the signature; and
- the signer possessed the private key corresponding to the trusted public key used by the verifier.

It does **not** by itself establish:

- the human identity controlling the key;
- an organizational identity;
- key custody quality;
- key freshness or revocation state.

Those claims require an external trust-distribution or identity-binding mechanism.

---

## 6. Response command success is not a verified response postcondition

The response flow does not treat a successful command return code as sufficient evidence of containment.

For a live stop exercise, the project verifies the named sandbox reached the expected stopped state.

Likewise, removing a local or Docker-managed credential binding proves only that the observed binding was removed from that local governance surface.

It does **not** prove a provider-side token or session was invalidated unless the provider exposes a trustworthy postcondition and that postcondition is actually verified.

Therefore:

```text
binding removed != upstream provider token revoked
```

---

## 7. MCP approval is not automatically separation of duties

Docker MCP policy mechanisms can provide confirmation / elicitation guardrails. The existence of an approval-oriented policy construct is useful policy evidence.

It is not automatically proof of independent administrator approval, step-up authentication or separation of duties.

The project keeps those stronger authorization claims non-green until direct evidence exists.

---

## 8. Governance Delta is not a causal statement

Governance Delta answers:

> **What changed between two independently verified assessment bundles?**

It can classify transitions such as:

- control improvement / regression;
- evidence gain / loss;
- evaluator recovery / error;
- scope change;
- unchanged.

It deliberately does not answer:

> **Why did the change happen?**

A status improvement after a governance change is not, by itself, proof that the governance change caused the improvement.

---

## 9. Controlled Experiment `ELIGIBLE` is not proof of causality

The Controlled Experiment Protocol checks whether required **measured** invariants match while the declared governance treatment differs.

Its outcomes are:

- `ELIGIBLE`;
- `NOT_ELIGIBLE`;
- `INSUFFICIENT_EVIDENCE`.

`ELIGIBLE` means only that the measured prerequisites for a bounded causal discussion are present.

It does **not** prove causality because:

- unmeasured confounders may remain;
- runtime systems may contain nondeterminism;
- evidence sources may be incomplete;
- the treatment fingerprint describes the declared/observed dimensions implemented by this lab, not every possible environmental difference.

The protocol exists to reject obviously uncontrolled comparisons, not to manufacture a causal claim.

---

## 10. Dry-run evidence is never live evidence

Dry-run mode exists to validate orchestration, schemas, packaging and fail-closed behavior without mutating Docker resources.

A dry run cannot claim:

- live sandbox isolation;
- live network enforcement;
- successful containment;
- credential revocation;
- quarantine from a real incident;
- Docker AI Governance runtime activity.

CI explicitly checks that these positive fields remain false / empty in dry-run flows.

---

## 11. Portable handoff is not automatically externally trusted

A portable customer pack can be internally verified, privacy-minimized and optionally signed.

That establishes transport integrity and authenticity relative to the supplied trust material.

It does not automatically establish that the public verification key belongs to a particular company or trusted authority.

For higher-assurance deployments, the final pack digest / public key should be distributed or anchored through an independent channel.

---

## Summary

The project deliberately keeps these boundaries separate:

```text
product presence        != observed enforcement
internal consistency    != external trust
signed artifact         != signer identity
recorded evidence       != source completeness
command success         != verified postcondition
local credential removal != provider revocation
before/after delta      != causality
experiment eligibility  != causal proof
dry run                  != live evidence
```

These distinctions are the core of the evidence model, not disclaimers added after the fact.
