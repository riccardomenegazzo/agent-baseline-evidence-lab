# Threat model

## Protected assets

- Host credentials and files outside the approved workspace.
- Agent credentials and delegated authority.
- Source code and generated artifacts.
- MCP tools and downstream services.
- Evidence required to reconstruct a run.

## Adversary / failure assumptions

The agent may receive malicious repository content or instructions, make a poor autonomous decision, invoke an unnecessary tool, or produce an unsafe artifact. V1 does **not** assume a malicious hypervisor, compromised host kernel, or compromised Docker control plane.

## Safe validation scenarios

V1 deliberately avoids destructive security testing. The live isolation evaluator can:

- place a random canary file in the host `/tmp` and verify that the same path is absent in the sandbox;
- use `sbx policy check network` to evaluate allow/deny decisions without making an outbound request;
- collect the active sandbox and policy state.

No real secret is created, read, or transmitted.

## Known gaps

- MCP organization-policy decisions are not ingested yet.
- Credential issuance/revocation is not exercised end to end.
- Model/tool traces are not yet correlated with target-system audit logs.
- Evidence manifesting detects tampering after collection but is not a substitute for signed/WORM storage.
