# Customer PoC: governing an AI coding agent with evidence

## Executive scenario

A platform engineering organization wants to make AI coding agents available to developers. Security and architecture teams need a defensible answer to five questions:

1. **What agent and components are in use?**
2. **What can the agent reach and do?**
3. **Which governance decisions were actually observed?**
4. **Can another reviewer verify the evidence without trusting screenshots or the originating workstation?**
5. **If governance changes, can we measure the before/after difference without claiming causality from an uncontrolled comparison?**

This PoC uses the Agent Baseline v1.0-draft as the control vocabulary and Docker Sandboxes as the primary execution surface.

> Community reference PoC. It does not provide Agent Baseline certification or official Docker conformance.

---

## PoC hypothesis

A coding-agent workflow can be made materially more reviewable when governance requirements are translated into:

- declared state;
- observable runtime checks;
- bounded adversarial scenarios;
- artifact validation;
- cryptographically linked evidence;
- explicit manual / unavailable evidence;
- independently verifiable customer handoffs.

The PoC is successful when it can demonstrate those properties **without converting product presence or missing telemetry into a pass**.

---

## In scope

### Community path

- Docker Sandbox runtime and policy observations where available;
- safe host-filesystem canary checks;
- network-policy decision checks;
- Docker MCP registration / policy posture;
- artifact and workspace validation;
- Agent Baseline assessment;
- hash-chained trace and evidence manifest;
- run attestation and Ed25519 authentication;
- disposable response exercise;
- portable customer evidence pack;
- Governance Delta;
- Controlled Experiment Protocol.

### Optional environment-dependent path

When the required Docker capabilities and licenses are available:

- Docker AI Governance local audit ingestion;
- observed MCP `tool_invocation` / `tool_execution` evidence;
- stronger audit correlation;
- environment-specific governance decision chains.

The optional path is an extension, not a prerequisite for understanding the community PoC.

---

## Out of scope

The PoC does not attempt to prove:

- model correctness or safety in all prompts;
- completeness of telemetry that was never emitted;
- organization-wide policy rollout from a single workstation;
- upstream provider credential revocation without a trustworthy provider postcondition;
- human/organization identity from possession of a signing key alone;
- causality from a simple before/after status change.

---

## Success criteria

Success criteria distinguish **evidence collected** from **control outcome**. A control is not required to become `PASS` for the PoC to be useful; an honest `PARTIAL` or `MANUAL` with a precise gap can itself satisfy the evidence-quality objective.

| ID | Success criterion | Evidence source | Acceptance condition |
|---|---|---|---|
| S1 | Agent has stable identity, owners, purpose and risk context | assessment declaration | required declared fields are present and evidenced |
| S2 | Run is bound to a unique sandbox identity | live-run capsule | sandbox identity is generated and preserved across run/response artifacts |
| S3 | Host-only canary is not visible inside the target sandbox | `sbx exec` probe | live postcondition observed, otherwise explicitly non-green |
| S4 | Required network decisions are checked against the named sandbox | `sbx policy check network` | expected allow/deny decisions are evidenced, otherwise explicit failure/gap |
| S5 | MCP registration identity is distinguished from generic MCP presence | registration inventory | expected registration name/endpoint can be reconciled when available |
| S6 | MCP policy posture is evaluated without claiming runtime enforcement | Cedar analysis | static conclusions are labelled as policy evidence, not enforcement evidence |
| S7 | Agent-modified workspace is validated | artifact/test hooks | configured validation commands execute against the disposable workspace |
| S8 | Evidence files are integrity-manifested | `manifest.sha256.json` | independent digest verification succeeds |
| S9 | Normalized trace is hash-linked and anchored | trace ledger + assessment | trace linkage, event count and head anchor verify |
| S10 | Run attestation binds to the evidence subject | attestation verifier | subject digest recomputes successfully |
| S11 | Response claims require verified postconditions | response artifact | dry-run never claims containment/revocation; live claims require observed state |
| S12 | Customer handoff excludes private signing keys and local path leakage | portable-pack verifier | privacy/trust-boundary checks pass |
| S13 | Two verified runs can be compared without a synthetic score | Governance Delta | delta recomputes from source bundles and classifies transitions explicitly |
| S14 | Causal discussion is gated by measured invariants | Controlled Experiment Protocol | result is `ELIGIBLE`, `NOT_ELIGIBLE` or `INSUFFICIENT_EVIDENCE` with reasons |

---

## Recommended PoC design

### Phase A — establish the evidence boundary

Run the non-mutating path first:

```bash
make install
make golden-demo-dry-run
```

This establishes a critical contract: dry-run can exercise orchestration and packaging mechanics, but it cannot manufacture live runtime, response or revocation evidence.

### Phase B — live baseline run

Before a customer-facing live run:

```bash
make baseline-sync
make signing-keygen
make baseline-lock-verify
make baseline-lock-sign
make baseline-lock-verify-signature
```

Then execute the live lifecycle:

```bash
make golden-demo
```

Retain the resulting verified evidence directory as the **before** run.

### Phase C — governance treatment

Change one bounded governance treatment while preserving the experimental invariants as far as the environment allows.

Examples of a treatment include:

- a network allow/deny policy change;
- a more restrictive MCP registration/profile;
- a different MCP Cedar policy declaration;
- a bounded capability-profile change.

Do **not** simultaneously change the task, initial workspace, agent identity and governance treatment if the goal is to discuss the governance change as a causal factor.

### Phase D — after run

Repeat the same workflow and retain the verified **after** evidence bundle.

### Phase E — measure the delta

```bash
make governance-delta \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

Review:

- control improvements / regressions;
- evidence gains / losses;
- evaluator recovery / errors;
- scope changes;
- unchanged controls.

### Phase F — gate causal interpretation

```bash
make experiment-protocol \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

Interpretation:

- `ELIGIBLE` — measured invariants match and the declared governance treatment differs;
- `NOT_ELIGIBLE` — at least one measured invariant differs, or no treatment change exists;
- `INSUFFICIENT_EVIDENCE` — at least one required invariant could not be established.

Even `ELIGIBLE` does not prove causality; it only prevents an obviously uncontrolled pair from being presented as controlled evidence.

### Phase G — customer handoff

```bash
make comparison-pack \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>

make comparison-pack-verify
```

The resulting package can be reviewed offline and contains public verification material without the local private signing key.

---

## Deliverables

A completed PoC should leave the customer with:

1. machine-readable assessment JSON;
2. human-readable assessment HTML;
3. verified evidence bundle;
4. run attestation and optional signature;
5. assurance summary;
6. response evidence where a live response exercise was executed;
7. privacy-minimized portable customer pack;
8. before/after Governance Delta where two runs exist;
9. Controlled Experiment statement;
10. signed comparison handoff where appropriate.

---

## Ten-minute demo path

For a concise stakeholder review:

1. explain the problem and claims boundary;
2. show `make golden-demo-dry-run` or the live `make golden-demo` path;
3. open one HTML assessment and its evidence manifest;
4. run `make verify` and `make assurance-latest`;
5. show Governance Delta + Controlled Experiment outputs for a before/after pair;
6. finish with the portable comparison pack and its offline verifier.

See [`DEMO_GUIDE.md`](DEMO_GUIDE.md) for the recommended talk track.

---

## Decision questions after the PoC

The PoC should end with architecture decisions, not only a demo result:

- Which controls must be centrally enforced versus locally observed?
- Which evidence should be retained and for how long?
- Which identifiers can correlate request, agent run, MCP action, policy decision and downstream artifact?
- Which events need external anchoring or organizational signing?
- What agent/component changes should trigger mandatory re-validation?
- Which customer cohorts share the same technical enablement pattern?
- Which optional Docker AI Governance signals materially improve the evidence model?

---

## PoC completion rule

The PoC is **not** complete because all controls are green.

It is complete when:

- the agreed scenarios executed;
- every automated conclusion has evidence;
- missing evidence is visible;
- the artifacts independently verify;
- the customer can explain what the evidence does and does not prove;
- next architecture decisions are explicit.
