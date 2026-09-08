# Customer Demo Guide

This guide is the shortest path for showing the project to a technical stakeholder without turning the session into a code tour.

The demo is designed around one question:

> **Can we move from an AI coding-agent governance claim all the way to a container artifact and customer handoff that another person can verify?**

## Interview format: five minutes

Use this compressed path for a hiring-manager conversation:

- **0:00–0:45** — customer problem and trust-chain diagram;
- **0:45–1:30** — live-demo preflight and what it refuses to assume;
- **1:30–3:15** — run or show the Customer Trust Flow;
- **3:15–4:20** — Decision Brief, lineage and signed handoff;
- **4:20–5:00** — one negative test proving that mutation invalidates trust.

The goal is not to show every feature. The goal is to demonstrate a reusable technical-enablement pattern:

> **problem → success criteria → governed execution → evidence → trusted artifact → decision → portable verification**

---

## 1. Prepare the Mac before the interview

For the local macOS path, Docker Sandboxes currently requires macOS Sonoma 14 or later on Apple silicon. The `sbx` CLI itself does not require Docker Desktop, but this project also performs a host-side Buildx trusted-artifact stage, so a working Docker daemon and Buildx are required for the complete live flow.

Install/update the project first:

```bash
make install
```

Prepare Docker Sandboxes outside the interview so no sign-in prompt appears during the demo:

```bash
sbx login
sbx secret set openai --oauth
```

Also initialize the local sandbox network-policy preset deliberately before the session if you have not already done so. For example:

```bash
sbx policy init balanced
```

Do not change a centrally managed organization policy for the sake of the demo. Organization policy remains authoritative when present.

Prepare the Agent Baseline source lock and local signing material:

```bash
make baseline-sync
```

Generate the local Ed25519 keypair only if it does not already exist:

```bash
test -f .abl/keys/attestation-private.json || make signing-keygen
```

Then bind and verify the baseline lock:

```bash
make baseline-lock-verify
make baseline-lock-sign
make baseline-lock-verify-signature
```

---

## 2. Run the interview-grade preflight

Before the live flow, run:

```bash
python -m agent_baseline_lab.demo_preflight \
  --scout-mode observe \
  --sandbox-smoke
```

The preflight checks the prerequisites that would otherwise fail at the worst possible moment:

- supported host platform;
- Python 3.11+;
- Docker CLI and daemon reachability;
- Docker Buildx;
- Docker Scout availability, without making it a hard requirement in `observe` mode;
- `sbx` CLI and local control-plane reachability;
- inspectable sandbox policy state;
- a host-managed OpenAI credential for Codex, without reading or persisting the token;
- verified Agent Baseline lock;
- local signing keypair;
- required demo assets;
- optionally, one disposable shell sandbox lifecycle.

With `--sandbox-smoke`, the preflight creates a temporary shell sandbox, records a per-sandbox deny rule for `exfiltration.invalid`, executes a trivial command, verifies that the deny rule is visible in sandbox policy state, and removes the sandbox.

This is deliberately stronger than checking whether an `sbx` binary exists.

The machine-readable result is written to:

```text
reports/demo-preflight.json
```

A green preflight still does **not** claim that the later Codex task, every runtime policy decision, Scout result, OCI trust chain or final disposition will succeed.

---

## 3. Open with the customer problem

Start from the repository home rather than the code.

Use this framing:

> An enterprise adopting coding agents needs more than “the agent is sandboxed”. It needs to know what the agent actually ran, what governance evidence was observed, what artifact came out of that workspace, whether SBOM/provenance bind to the artifact, whether policy checks passed, and whether a reviewer can verify the whole chain independently.

Then point out two deliberate design choices:

- there is no synthetic security score;
- unsupported claims remain non-green.

---

## 4. Safe path when you do not want live mutation

The complete non-mutating lifecycle is:

```bash
make customer-trust-dry-run
```

What this demonstrates:

- assessment, assurance, trusted-artifact and handoff orchestration are wired together;
- the handoff can be built, signed and independently verified;
- privacy checks remain active;
- dry-run cannot create agent-to-artifact lineage;
- dry-run cannot claim live Docker containment or Scout enforcement.

What it does **not** demonstrate:

- live Docker Sandbox isolation;
- live network enforcement;
- a real Buildx OCI artifact;
- real SBOM/provenance subject binding;
- a live Docker Scout result;
- live MCP execution or provider-side revocation.

This fail-closed behavior is also exercised by the dedicated `customer-trust` CI workflow.

---

## 5. Run the live Customer Trust Flow

For the first manager demo, use Docker Scout in observation mode:

```bash
abl-trust --scout-mode observe
```

Equivalent repository target:

```bash
make customer-trust SCOUT_MODE=observe
```

For MCP-focused environments:

```bash
make customer-trust-mcp SCOUT_MODE=observe
```

The live lifecycle is:

```text
readiness + signed baseline lock
  ↓
unique Docker Sandbox + real Codex task
  ↓
Agent Baseline assessment + assurance
  ↓
agent-modified workspace
  ↓
Docker Buildx OCI artifact
  ├─ SPDX SBOM
  └─ SLSA provenance
  ↓
OCI graph + attestation verification
  ↓
optional Docker Scout policy evidence
  ↓
agent → workspace → artifact lineage
  ↓
Customer Decision Brief
  ↓
SARIF + signed Customer Trust Handoff
```

The coding task is intentionally small and customer-readable: add a `/health` endpoint, update tests, validate the application, and stay inside the declared capability boundary.

The important result is not “how many controls are green”. The important result is whether the evidence chain is internally consistent, independently verifiable and explicit about what remains unproven.

---

## 6. Explain Docker Scout modes

The project intentionally separates observation from gating:

```text
off      Scout is excluded from the decision boundary
observe  Scout evidence is collected but does not hard-block the disposition
gate     Scout must pass before EVIDENCE_READY is possible
```

For a first manager demo, prefer:

```bash
abl-trust --scout-mode observe
```

This lets you show the integration without making the entire demonstration depend on one local Scout policy configuration.

Use `gate` only when Docker Scout is an agreed PoC acceptance criterion.

---

## 7. Show four artifacts, not forty

### A. Customer Trust Flow HTML

Open:

```text
reports/<run-id>.trust/customer-trust-flow.html
```

Use it to explain the complete chain from agent execution to signed handoff.

### B. Customer Decision Brief

Open:

```text
reports/<run-id>.trust/customer-decision.portable.html
```

Discuss the disposition:

- `BLOCKED`;
- `CONDITIONAL`;
- `EVIDENCE_READY`;
- `DRY_RUN`.

Stress that `EVIDENCE_READY` means the configured PoC evidence boundary was satisfied — not production approval or Docker certification.

### C. Trusted artifact + lineage

Open:

```text
reports/<run-id>.trust/trusted-artifact.portable.json
reports/<run-id>.trust/agent-artifact-lineage.json
```

Explain that the project verifies:

- the OCI graph;
- SBOM/provenance presence **and subject binding**;
- the artifact digest;
- that the post-agent workspace digest matches the workspace used for lineage;
- that the artifact did not change after the trust statement.

### D. Final handoff

The final file is:

```text
reports/<run-id>.customer-trust-handoff.zip
```

Verify it independently:

```bash
make trust-handoff-verify
```

The verifier checks the handoff manifest, member digests/sizes, nested customer evidence pack, nested signatures, private-key exclusion and lineage signature where present.

---

## 8. End with a controlled negative test

Do not tamper with the successful live evidence during an interview. Instead, use the deterministic regression tests that model the same trust failure:

```bash
pytest -q tests/test_artifact_lineage.py -k mutation
```

The two tests prove that lineage creation is rejected when either:

- the workspace is modified after the recorded agent run; or
- the OCI archive is modified after trusted-artifact verification.

This is a stronger closing moment than another green dashboard because it demonstrates that the trust statement has a real invalidation condition.

Suggested sentence:

> The important property here is not that the system can produce a green artifact. It is that the same verifier refuses the claim when the workspace or artifact no longer matches the evidence chain.

---

## 9. Developer/security integration

The flow also produces SARIF:

```text
reports/<run-id>.trust/agent-governance.sarif
```

This is useful to explain that the pattern can feed existing security tooling rather than requiring a custom dashboard.

---

## 10. Optional before/after story

If the discussion moves from “is this run reviewable?” to “did governance change anything?”, switch to the comparative path.

```bash
make governance-delta \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

Then:

```bash
make experiment-protocol \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

Explain the distinction:

```text
Governance Delta
  = what changed?

Controlled Experiment Protocol
  = were the measured prerequisites for causal discussion present?
```

Do not mix this with the single-run Customer Trust decision; they answer different questions.

---

## Optional Docker MCP / AI Governance path

When the relevant Docker capabilities are available:

```bash
make mcp-register-dhi
make customer-trust-mcp SCOUT_MODE=observe
```

Use this path to discuss:

- controlled MCP registration;
- Cedar policy posture;
- direct-MCP bypass versus governed tool paths;
- optional AI Governance audit evidence;
- why static policy presence is not the same as observed enforcement.

The community path remains useful without licensed AI Governance signals.

---

## Questions the demo should invite

A strong technical review should naturally lead to questions such as:

- Which controls should be locally observed versus centrally enforced?
- Should Scout be `observe` or `gate` for this customer cohort?
- Which identifiers should correlate developer request, agent run, MCP decision and resulting image?
- Which artifact evidence needs external organizational identity rather than a local key?
- Which policy or base-image changes should force re-validation?
- Which parts of this PoC could become a reusable enablement kit for many customers?

---

## Claims boundary to state explicitly

The project does not claim:

- Agent Baseline certification;
- official Docker conformance;
- that an SBOM proves an artifact is secure;
- that provenance proves source code is correct;
- that Scout passing means vulnerability-free;
- that lineage proves runtime behavior is safe;
- that a valid Ed25519 signature proves organizational identity;
- that a before/after improvement proves causality;
- provider-side revocation without a verified provider postcondition.

That restraint is part of the architecture.
