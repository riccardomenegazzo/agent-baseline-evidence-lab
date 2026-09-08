# Governance Delta — verified before/after evidence

The Governance Delta turns two independently verified assessment runs into a customer-facing before/after artifact without inventing a security score.

Its question is deliberately narrow:

> **What changed in the evidence between these two verified runs?**

It does **not** answer, by itself, whether a governance change caused those differences.

## Why this exists

A customer PoC often starts with one state, applies a governance or architecture change, then runs the same validation again. A useful technical asset should make the delta visible while preserving the original evidence anchors.

The delta therefore binds both sides to:

- assessment run ID;
- Agent Baseline version;
- evidence-manifest SHA-256;
- trace-head SHA-256;
- trace event count;
- assessment JSON SHA-256.

Both bundles must verify before the comparison is created. The baseline version and control-ID set must also match.

## Run it

After producing two evidence bundles:

```bash
make governance-delta \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

This creates:

```text
reports/governance-delta.json
reports/governance-delta.html
```

Verify it by recomputing the comparison from the original bundles:

```bash
make governance-delta-verify \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

If an Ed25519 keypair has already been created, sign the exact JSON comparison:

```bash
make governance-delta-sign \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>

make governance-delta-sign-verify
```

The signature proves possession of the configured private key. It does not establish an external organizational identity unless the public key is independently bound to one.

## Change classifications

| Classification | Meaning |
|---|---|
| `unchanged` | The control status is identical in both verified runs. |
| `control-improvement` | `FAIL → PARTIAL/PASS` or `PARTIAL → PASS`. |
| `control-regression` | `PASS → PARTIAL/FAIL` or `PARTIAL → FAIL`. |
| `evidence-gain` | A previously `MANUAL` control became evaluated. The new result may be `PASS`, `PARTIAL`, or `FAIL`. |
| `evidence-loss` | A previously evaluated control became `MANUAL`. |
| `evaluator-recovery` | A previous evaluator `ERROR` became a non-error result. |
| `evaluator-error` | A previously non-error result became `ERROR`. |
| `scope-change` | One side is `N/A`; applicability changed and should not be treated as improvement/regression. |
| `other-change` | A status transition that does not fit one of the explicit semantic categories above. |

### Why `MANUAL → FAIL` is evidence gain

Suppose the first run could not observe an authorization decision, so the control was `MANUAL`. The second run adds the relevant runtime telemetry and proves that the decision actually fails the requirement.

That is **better evidence and a negative security finding at the same time**.

Calling it a simple regression would imply the environment necessarily got worse. Calling it an improvement would hide the failing result. `evidence-gain` preserves both facts.

## No security score

The project intentionally does not rank:

```text
PASS > PARTIAL > MANUAL > ERROR > FAIL
```

as a single numeric scale.

Those states have different semantics. `ERROR` is an evaluator problem, `MANUAL` is an evidence gap, and `FAIL` may actually represent stronger observability than `MANUAL`.

The report therefore exposes **counts by transition class**, never a synthetic trust percentage.

## Comparability gates

The delta fails closed when:

- either evidence bundle does not verify;
- baseline versions differ;
- control-ID sets differ;
- the recorded delta no longer matches a fresh recomputation.

A different `agent_id` does not make the artifact unverifiable, but it produces a warning because the result is cross-agent evidence rather than a clean controlled before/after experiment.

## Causal claims boundary

A verified before/after delta is not proof of causation.

For a stronger customer experiment, keep these variables stable where possible:

- agent and model;
- task/prompt digest;
- application/workspace starting state;
- baseline version;
- Docker/Sandbox version;
- MCP server identities;
- timing and external dependencies.

Then change the governance condition intentionally and rerun the same validation.

The delta can prove **what the two evidence bundles say changed**. Experimental design is what supports an argument about **why** it changed.

## Suggested CXE-T PoC flow

```text
baseline run
    │
    ├── verified manifest + trace
    │
    ▼
apply agreed governance change
    │
    ▼
second run
    │
    ├── verified manifest + trace
    │
    ▼
Governance Delta
    │
    ├── improvements
    ├── regressions
    ├── evidence gains/losses
    ├── evaluator recovery/errors
    └── scope changes
    │
    ▼
signed comparison artifact
```

This makes the repository useful as a repeatable customer evaluation framework rather than a one-off product demonstration.
