# Customer Demo Guide

This guide is the shortest path for showing the project to a technical stakeholder without turning the session into a code tour.

The demo answers one question:

> **Can we move from an AI coding-agent governance claim all the way to a container artifact and customer handoff that another person can verify?**

## Five-minute interview format

- **0:00–0:45** — customer problem and trust-chain diagram;
- **0:45–1:20** — fail-closed live preflight;
- **1:20–3:10** — Customer Trust Flow;
- **3:10–4:20** — Decision Brief, lineage and signed handoff;
- **4:20–5:00** — one mutation test proving that trust can be invalidated.

The story is:

> **problem → success criteria → governed execution → evidence → trusted artifact → decision → portable verification**

Do not try to show every module in the repository.

---

## 1. Prepare the Mac before the meeting

For the local macOS path, Docker Sandboxes currently requires macOS Sonoma 14 or later on Apple silicon. The complete trust flow also needs a working Docker daemon and Docker Buildx for the trusted-artifact stage.

Install/update the project:

```bash
make install
```

Prepare Docker Sandboxes outside the meeting so no authentication prompt appears during the demo:

```bash
sbx login
sbx secret set openai --oauth
```

Initialize the local sandbox policy deliberately if one is not already configured:

```bash
sbx policy init balanced
```

Do not replace a centrally managed organization policy for the sake of the demo.

Prepare the Agent Baseline source lock and local signing material:

```bash
make baseline-sync
test -f .abl/keys/attestation-private.json || make signing-keygen
make baseline-lock-verify
make baseline-lock-sign
make baseline-lock-verify-signature
```

---

## 2. Run the interview-grade preflight

The installed trust CLI has a preflight-only mode:

```bash
abl-trust --preflight-only --preflight-smoke --scout-mode observe
```

Equivalent standalone command:

```bash
abl-preflight --scout-mode observe --sandbox-smoke
```

The preflight checks:

- supported host platform;
- Python 3.11+;
- Docker CLI and daemon reachability;
- Docker Buildx;
- Docker Scout availability, without making Scout a hard requirement in `observe` mode;
- `sbx` CLI and local control-plane reachability;
- inspectable sandbox policy state;
- a host-managed OpenAI credential for Codex, without reading or persisting the token;
- verified Agent Baseline lock;
- local Ed25519 signing keypair;
- required demo assets;
- optionally, one disposable shell-sandbox lifecycle.

With `--preflight-smoke`, the preflight creates a temporary shell sandbox, records a per-sandbox deny rule for `exfiltration.invalid`, executes a trivial command, verifies the deny rule in policy state and removes the sandbox.

The machine-readable result is written to:

```text
reports/demo-preflight.json
```

A green preflight proves only that prerequisites were observed. It does not predict the later Codex task, Scout result, OCI verification or final disposition.

Live `abl-trust` runs execute the non-destructive preflight automatically before starting the trust lifecycle. Dry-runs intentionally skip host probing.

---

## 3. Open with the customer problem

Start from the repository home rather than the code.

Suggested framing:

> An enterprise adopting coding agents needs more than “the agent is sandboxed”. It needs to know what the agent actually ran, what governance evidence was observed, what artifact came out of that workspace, whether SBOM/provenance bind to the artifact, whether policy checks passed, and whether a reviewer can verify the whole chain independently.

Point out two deliberate choices:

- there is no synthetic security score;
- unsupported claims remain non-green.

---

## 4. Safe path when you do not want live mutation

```bash
make customer-trust-dry-run
```

Dry-run demonstrates orchestration, evidence packaging, signatures, privacy checks and independent handoff verification.

It deliberately cannot claim:

- live Docker Sandbox isolation;
- live network enforcement;
- a real OCI build;
- live SBOM/provenance subject binding;
- Docker Scout enforcement;
- positive agent-to-artifact lineage.

The dedicated `customer-trust` GitHub Actions workflow continuously tests this fail-closed contract.

---

## 5. Run the live Customer Trust Flow

For the first manager demo use Scout in observation mode:

```bash
abl-trust --scout-mode observe
```

The live CLI performs its fail-closed preflight first. If a required prerequisite is red, the agent run does not start.

Repository equivalent:

```bash
make customer-trust SCOUT_MODE=observe
```

For MCP-focused environments:

```bash
abl-trust --profile mcp --scout-mode observe
```

The lifecycle is:

```text
preflight + signed baseline lock
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

The coding task is intentionally small and customer-readable: add a `/health` endpoint, update tests, validate the application and stay inside the declared capability boundary.

---

## 6. Explain Docker Scout modes

```text
off      Scout is outside the decision boundary
observe  Scout evidence is collected but does not independently hard-block the disposition
gate     Scout must pass before EVIDENCE_READY is possible
```

For the first demo prefer:

```bash
abl-trust --scout-mode observe
```

Use `gate` only when Scout is an agreed PoC acceptance criterion.

---

## 7. Present the result without hunting for files

After the flow finishes, run:

```bash
abl-present
```

This helper verifies the final Customer Trust Handoff and its Ed25519 signature against the selected local public key. It also binds each displayed HTML/JSON artifact to the signed ZIP member, checks the run ID and handoff digest, and checks the summary statuses against signed evidence. Modified neighboring reports are rejected even when the ZIP itself still verifies.

The selected local key does not establish signer identity. The helper does not rerun Docker, rebuild the OCI artifact or recheck the live workspace; lineage status reflects the signed packaged evidence. For those checks, use the underlying verifiers with their original inputs.

For a rehearsed presentation, select the exact run explicitly:

```bash
abl-present --run-id <assessment-run-id> --open
```

Without `--run-id`, a live run takes precedence over a newer dry-run. Always read the run ID and dry-run flag before explaining the result.

To open the two presentation pages automatically:

```bash
abl-present --open
```

Machine-readable form:

```bash
abl-present --json
```

Show these in order:

1. **Customer Trust Flow HTML** — the complete evidence chain and final disposition;
2. **Customer Decision Brief** — `BLOCKED`, `CONDITIONAL`, `EVIDENCE_READY` or `DRY_RUN`;
3. **Trusted Artifact + lineage** — OCI integrity, SBOM/provenance subject binding and workspace/artifact linkage;
4. **Signed Customer Trust Handoff** — portable verifier boundary for another reviewer.

`EVIDENCE_READY` means that the configured PoC evidence boundary was satisfied. It is not production approval or Docker certification.

---

## 8. End with a controlled negative test

Do not modify the successful live evidence during the interview. Use the deterministic regression tests instead:

```bash
python -m pytest -q tests/test_artifact_lineage.py -k mutation
python -m pytest -q tests/test_present.py -k 'changed or swapped or tampered'
```

They prove that lineage creation is rejected when either:

- the workspace is modified after the recorded agent run; or
- the OCI archive is modified after trusted-artifact verification.

Suggested closing line:

> The important property is not that the system can produce a green artifact. It is that the same verifier refuses the claim when the workspace or artifact no longer matches the evidence chain.

---

## 9. Optional before/after story

If the discussion moves from “is this run reviewable?” to “did governance change anything?”, use:

```bash
make governance-delta BEFORE=evidence/abl-<before> AFTER=evidence/abl-<after>
make experiment-protocol BEFORE=evidence/abl-<before> AFTER=evidence/abl-<after>
```

Keep the distinction explicit:

```text
Governance Delta
  = what changed?

Controlled Experiment Protocol
  = were the measured prerequisites for causal discussion present?
```

A valid delta is not automatically a valid causal experiment.

---

## 10. Optional Docker MCP / AI Governance path

When the relevant Docker capabilities are available:

```bash
make mcp-register-dhi
abl-trust --profile mcp --scout-mode observe
```

Use this path to discuss controlled MCP registration, Cedar policy posture, direct-MCP bypass versus governed tool paths, optional AI Governance audit evidence and why policy presence is not the same as observed enforcement.

The community path remains useful without licensed AI Governance signals.

---

## Questions the demo should invite

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


## Explain the project as a customer engagement

A concise opening:

> I built this around a customer conversation: a team wants to adopt coding agents, but its security reviewers need evidence before they can agree on the next step. I wanted to turn that conversation into a small, reproducible engagement. We agree on a task and a control boundary, run the task, collect the evidence and produce a decision brief with blockers and next actions. A second reviewer can verify the signed handoff offline. Where the evidence is missing, the result stays conditional or blocked. The dry-run demonstrates the workflow; live runtime claims require a real run in the customer environment.

If asked how this relates to customer experience, explain the practical work: clarify the customer's concern, agree on observable success criteria, reproduce the issue, identify which layer owns the gap, and leave a handoff another engineer can use. The project's value is the quality of that investigation and handoff.

If asked what is original, distinguish the composition from the tools. Docker, BuildKit, Scout, OCI and cryptographic signatures already exist. The contribution is connecting run-specific governance evidence, artifact verification and customer-specific decisions while preserving their different limitations.

If asked how you know it works, show the tests that reject altered inputs and one reproducible dry-run or a previously collected live run. Explain exactly which environment produced that evidence. Do not describe mocked integration inputs or dry-run output as observed Docker enforcement.

If asked about business impact, propose measuring time from the initial question to a reproducible report, reviewer follow-up rounds and time to close an evidence gap in a real pilot. No customer deployment or measured business improvement is implied by the current test suite.

If the live environment fails preflight, use the rehearsed dry-run and explain the missing prerequisite. A useful CXE demonstration includes diagnosing a limitation and giving a concrete next action; it does not require every result to be green.
