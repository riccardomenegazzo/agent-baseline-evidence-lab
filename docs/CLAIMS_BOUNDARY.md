# Claims boundary

This project is intentionally strict about what an automated result means.

## What a result means

A `PASS` means that the **specific implemented evaluator** collected enough evidence for the check it owns. It is not an Agent Baseline certification, a Docker product attestation, or proof that every clause of a broader upstream control is satisfied.

A `PARTIAL` is often the most accurate result. For example, observing Docker Sandbox host-canary separation and expected network decisions is strong evidence for part of `CON-03`, but the upstream control also covers credential delivery, compute, duration, process count, persistence and retained state. The evaluator therefore stays `PARTIAL` until those dimensions are evidenced too.

## Evidence integrity

The lab uses two complementary mechanisms:

1. a SHA-256 manifest over every file in the run evidence directory;
2. an append-only NDJSON event ledger where every event hashes the previous event.

This makes post-run changes detectable **relative to the recorded bundle and trace head**. It does not make the bundle tamper-proof against an actor who can rewrite every artifact and every external copy of the head hash. A production system should anchor the final digest outside the assessed environment, for example in a transparency service, signed release, or independent evidence store.

## MCP approval nuance

Docker MCP policies support `@requireApproval`, but Docker documents this as an MCP elicitation/confirmation guardrail. It is not, by itself, independent administrator approval or separation of duties. The lab therefore does not map the presence of `@requireApproval` directly to `AUT-05 = PASS`.

## Product presence is never evidence by itself

The following shortcuts are explicitly forbidden in this repository:

- `Docker Sandbox exists -> CON-03 PASS`
- `MCP Gateway exists -> authorization PASS`
- `Cedar policy file exists -> enforcement PASS`
- `SBOM exists -> software supply chain PASS`

The project must observe the state, decision, action, or outcome required by the evaluator and preserve the resulting evidence.
