# Implementation note: testing independent evidence, truncation and omission

Status: implementation feedback candidate for Agent Baseline discussion. This is **not** an accepted upstream interpretation or control change.

Related upstream discussion: [`agentbaseline/agentbaseline#26`](https://github.com/agentbaseline/agentbaseline/issues/26), which argues that evidence should be checkable outside the operator trust boundary and highlights the difference between alteration detection and omission detection.

Agent Baseline's contributing guide explicitly invites proposals for **test methods**: ways to check whether a control is actually met. This note records what happened when that question was implemented rather than answered only in prose.

## Question

What does an evidence verifier actually prove when the evidence producer controls:

- the event ledger;
- the assessment metadata;
- the exported manifest;
- the verification command?

And which additional mechanisms are needed to distinguish:

```text
an event did not happen
```

from:

```text
an event happened but never entered the evidence set
```

## Reproducible matrix

Run a normal assessment first:

```bash
make demo
```

Then execute the attack matrix against the resulting evidence directory:

```bash
python -m agent_baseline_lab.evidence_matrix \
  evidence/abl-... \
  --output reports/evidence-verification-matrix.json
```

The implementation tests four cases against disposable copies of the original bundle.

### 1. Single-file alteration

Attack:

```text
change one manifested evidence file
leave manifest unchanged
```

Expected result:

```text
internal verification: FAIL
external-anchor verification: FAIL
```

Reason: the file digest no longer matches its manifest entry.

### 2. Trace truncation without anchor rewrite

Attack:

```text
remove the final event from the trace
leave assessment trace head/count unchanged
leave manifest unchanged
```

Expected result:

```text
internal verification: FAIL
external-anchor verification: FAIL
```

The verifier has three independent reasons to reject this state:

- trace file digest changed;
- observed trace head no longer matches assessment metadata;
- observed event count no longer matches assessment metadata.

This is useful exported-trace truncation detection.

### 3. Coordinated rewrite

Attack:

```text
remove the final trace event
rewrite assessment trace head/count to match the shorter trace
regenerate the local evidence manifest
```

Expected result:

```text
internal verification: PASS
verification against original external hashes: FAIL
```

This is the most important result.

A verifier that receives only a self-consistent bundle from an evidence producer able to rewrite every local anchor cannot determine that an earlier version contained another event. Hash chains and manifests provide tamper evidence only relative to an anchor the attacker cannot also rewrite.

The current lab therefore labels its local structure **tamper-evident**, not independently authentic, and supports externally pinned manifest and trace-head hashes.

### 4. Event never emitted

Assumption:

```text
a material source event happened
but the event was never sent into the evidence pipeline
```

Expected result:

```text
internal verification: PASS
verification against an external hash of the same incomplete export: PASS
```

There is no altered artifact to detect. A hash cannot prove the existence of information that never entered the hashed set.

This separates two properties:

```text
artifact integrity
```

and:

```text
source completeness
```

They need different test methods.

## Proposed vendor-neutral test method

The following could be used as non-normative implementation guidance or as input to an evidence-verification control discussion.

### Integrity / independent rewrite test

1. Export the evidence record and all verification material.
2. Store at least one verification anchor outside the evidence producer's rewrite boundary: for example a signed checkpoint, transparency-log entry, externally retained digest, or other independently verifiable commitment.
3. Verify the untouched export on infrastructure outside the producer boundary.
4. Alter one material record. Verification must fail.
5. Truncate one material record. Verification must fail.
6. Rewrite local metadata/manifests to make the altered export self-consistent. Verification against the independent anchor must still fail.

The exact cryptographic implementation is intentionally unspecified.

### Completeness / omission test

Integrity alone is insufficient. Use an independent **completeness witness** for a bounded scope.

The witness contains:

```json
{
  "schema_version": 1,
  "witness_id": "...",
  "scope": "bounded run / approval / incident",
  "source": "independent source-of-record",
  "expected_event_ids": ["event-a", "event-b", "event-c"],
  "checkpoint": "optional external sequence/checkpoint commitment"
}
```

Then reconcile the exported evidence:

```bash
python -m agent_baseline_lab.completeness \
  witness.json observed-event-ids.json
```

If the witness says:

```text
A B C
```

and the exported evidence contains:

```text
A C
```

verification fails with:

```text
missing_event_ids = [B]
```

This turns a known omission into a testable failure.

The witness itself must come from a trust boundary independent enough for the assurance claim being made. Reconciling against a witness generated by the same compromised producer simply moves the problem.

## Implementation connection to runtime audit

The lab also implements a bounded runtime correlation canary for Docker AI Governance audit evidence. A run-scoped `.correlation.invalid` marker is generated from the live agent session ID and searched for in finalized audit `resource_id` records.

That experiment reinforces the same distinction:

- exact marker observed in an independent runtime record → strong bounded correlation evidence;
- only one daemon session in the same time window → supporting evidence, not exact task causality;
- in-progress audit file only → pending finalization, not negative evidence;
- no marker/source witness → absence cannot be interpreted as proof the action never happened.

The underlying test method is vendor-neutral: create or identify a source event with an independently observable identifier, then require the exported evidence to reconcile to it.

## What this implementation suggests

A useful evidence assurance model appears to need at least three separable properties:

| Property | Example test |
|---|---|
| **Integrity** | Alter an exported record and require verification failure. |
| **Independent anchoring** | Rewrite all producer-local hashes and require failure against an external commitment. |
| **Completeness for a bounded scope** | Compare against an independently derived expected event set/checkpoint and require missing events to fail. |

Calling all three simply "tamper resistance" risks hiding materially different failure modes.

## Claims boundary

This note does not claim that:

- SHA-256 manifests are sufficient assurance architecture;
- one specific transparency log, signer, vendor or evidence format should be normative;
- a completeness witness proves events outside the witness scope;
- a source-of-record is automatically trustworthy;
- the current lab provides full independent authenticity — its run and response-link statements are deliberately unsigned today.

The implementation is intended to supply reproducible evidence for the control-design discussion, not prescribe a vendor implementation.
