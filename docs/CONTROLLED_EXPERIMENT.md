# Controlled Experiment Protocol

A Governance Delta answers:

> **What changed between two verified assessments?**

It does **not** answer:

> **Did the governance change cause the observed difference?**

The Controlled Experiment Protocol exists to keep those two claims separate.

## Goal

Before a before/after result is treated as eligible for causal discussion, the lab checks that the required **measured invariants** are the same and that a governance treatment actually changed.

The protocol is fail-closed. Missing evidence does not become a match.

## Run it

```bash
make experiment-protocol \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

Outputs:

```text
reports/controlled-experiment.json
reports/controlled-experiment.html
```

Verify the statement by recomputing it from both evidence bundles:

```bash
make experiment-protocol-verify \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

Sign it with the same local Ed25519 trust material used by the evidence lifecycle:

```bash
make experiment-protocol-sign \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>

make experiment-protocol-sign-verify
```

## Required measured invariants

The protocol requires evidence for these dimensions:

| Invariant | Evidence source | Why it matters |
| --- | --- | --- |
| Agent Baseline version | `assessment.json` | Prevents comparing different control definitions. |
| Agent identity | assessment metadata | Avoids silently comparing different agents. |
| Task ID | execution capsule / assessment config | Keeps the declared task stable. |
| Task SHA-256 | execution capsule | Proves the actual task bytes are the same without persisting the prompt. |
| Initial workspace SHA-256 | execution capsule | Proves both runs start from the same code/content state. |
| Agent runtime | execution capsule | Prevents changing the agent implementation between arms. |
| Docker Sandbox runtime fingerprint | runtime evidence | Prevents a measured Docker runtime change from being silently treated as a governance effect. |

If any required invariant is unavailable, the result is:

```text
INSUFFICIENT_EVIDENCE
```

If an invariant is observed and differs, the result is:

```text
NOT_ELIGIBLE
```

## Governance treatment

The protocol derives a deterministic treatment fingerprint from the evidence-safe assessment configuration. The projection currently covers:

- required network allows and denies;
- static MCP server registrations;
- sandbox capability profile;
- MCP policy-file declarations;
- declared agent access;
- declared agent capabilities.

A controlled before/after treatment comparison requires this fingerprint to differ.

If all invariants match but the treatment is unchanged, the pair is `NOT_ELIGIBLE`: it can be useful repeatability evidence, but it is not a treatment experiment.

## Eligibility states

### `ELIGIBLE`

All required measured invariants match and the governance treatment differs.

This means the pair is **eligible for bounded causal interpretation**. It does not mean causality has been proven.

### `NOT_ELIGIBLE`

At least one measured invariant differs, or no treatment difference was observed.

A Governance Delta can still be useful; it simply must not be presented as controlled causal evidence.

### `INSUFFICIENT_EVIDENCE`

One or more required invariants could not be established from the supplied evidence.

This is deliberately different from `NOT_ELIGIBLE`: the lab is saying it cannot establish comparability rather than claiming a known mismatch.

## Example

```text
BEFORE RUN                       AFTER RUN
──────────                       ─────────
Task digest A              =     Task digest A
Workspace digest B         =     Workspace digest B
Agent: codex               =     Agent: codex
Sandbox runtime digest C   =     Sandbox runtime digest C

Governance treatment X     ≠     Governance treatment Y
                                │
                                ▼
                             ELIGIBLE
```

Contrast that with:

```text
Task digest A              ≠     Task digest D
                                │
                                ▼
                          NOT_ELIGIBLE
```

and:

```text
Sandbox runtime digest     ?     missing
                                │
                                ▼
                    INSUFFICIENT_EVIDENCE
```

## Why this matters in a customer PoC

A strong PoC should answer two different questions without conflating them:

1. **Did the control/evidence posture change?** — Governance Delta.
2. **Were the two observations sufficiently controlled, based on measured evidence, to discuss the governance treatment as a causal factor?** — Controlled Experiment Protocol.

That separation prevents an attractive before/after result from becoming an unsupported security claim.

## Claims boundary

`ELIGIBLE` means the required **measured** invariants match and the declared treatment differs. Unmeasured confounders can still exist. The protocol does not establish official Docker or Agent Baseline conformance, guarantee complete telemetry, or prove causality by itself.

See [`CLAIMS_BOUNDARY.md`](CLAIMS_BOUNDARY.md) for the complete trust and interpretation boundary.
