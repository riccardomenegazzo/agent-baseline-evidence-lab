# Evidence model

An assessment result is useful only when another reviewer can answer four questions:

1. **What did we expect?**
2. **What did we observe?**
3. **Which control was evaluated?**
4. **Can we detect if the evidence changed afterwards?**

Each evaluator therefore emits run-scoped files below `evidence/<run-id>/controls/<control-id>/`. The final `manifest.sha256.json` records SHA-256 digests for every collected artifact.

## Status semantics

| Status | Meaning |
|---|---|
| `PASS` | The evaluator observed enough evidence for the narrowly implemented check. |
| `FAIL` | The observed state contradicts the implemented check or a required field is absent. |
| `PARTIAL` | Useful evidence exists, but the complete upstream requirement is broader than the implemented check. |
| `MANUAL` | V1 cannot collect sufficient evidence automatically. |
| `N/A` | The control has been explicitly scoped out with justification. |
| `ERROR` | The evaluator itself failed; this never degrades to PASS. |

A `PASS` is **not** an official Agent Baseline certification. It means only that the specific evaluator described in the report passed for that run.
