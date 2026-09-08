# Agent Baseline Evidence Lab

[![CI](https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/actions/workflows/ci.yml)
[![Customer Trust](https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/actions/workflows/customer-trust.yml/badge.svg)](https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/actions/workflows/customer-trust.yml)
[![Release](https://img.shields.io/github/v/release/riccardomenegazzo/agent-baseline-evidence-lab?display_name=tag)](https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/releases/latest)
[![Python](https://img.shields.io/badge/python-%3E%3D3.11-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**A customer-ready reference PoC that turns AI coding-agent governance into reproducible evidence — from governed execution to a verifiable container artifact and signed customer handoff.**

> Community project. Not an official Docker, Snyk, Keycard, or Agent Baseline project. It does **not** issue certifications or claim official conformance.

AI-agent security guidance is easy to describe and much harder to prove. This project asks a narrower question:

> **For this agent, in this environment, during this run: what can we actually prove — and can we link that evidence to the exact software artifact the agent produced?**

It uses the **Agent Baseline v1.0-draft** as a control vocabulary and **Docker Sandboxes** as the primary execution surface. It then extends the evidence chain through Docker Buildx, OCI attestations, optional Docker Scout policy evaluation, agent-to-artifact lineage, a decision brief, SARIF, and a privacy-safe signed handoff.

There is deliberately **no marketing security score**.

---

## The customer trust chain

The strongest path in the repository is the end-to-end **Customer Trust Flow**:

```mermaid
flowchart LR
    A[AI coding task] --> B[Docker Sandbox]
    B --> C[Agent-run capsule]
    C --> D[Agent Baseline assessment]
    D --> E[Independent assurance]
    E --> F[Docker Buildx]
    F --> G[OCI + SBOM + provenance]
    G --> H[OCI graph verification]
    H --> I[Optional Docker Scout]
    I --> J[Agent to artifact lineage]
    J --> K[Decision Brief + SARIF]
    K --> L[Signed customer handoff]
```

The project does not treat those boxes as equivalent claims. Each stage has its own evidence source, verifier, trust boundary and failure semantics.

A positive live lineage is produced only when the project can verify all of the following:

1. the selected agent-run evidence manifest is valid;
2. the build context is the workspace recorded by that agent run;
3. the current workspace SHA-256 matches the recorded post-task snapshot;
4. the trusted-artifact stage is `VERIFIED`;
5. the OCI archive digest still matches the trusted-artifact report;
6. the complete referenced OCI graph verifies recursively;
7. SPDX SBOM evidence exists;
8. SLSA provenance evidence exists;
9. the attestations are subject-bound to the referred runnable image manifest.

Mutating the workspace after the agent run or altering the OCI archive after verification invalidates the chain. Those negative cases are covered by automated tests.

See [`docs/CUSTOMER_TRUST_FLOW.md`](docs/CUSTOMER_TRUST_FLOW.md).

---

## Why this exists

An enterprise adopting coding agents needs stronger answers than:

- “the agent runs in a sandbox”;
- “we have an MCP policy”;
- “audit logs exist”;
- “the stop command succeeded”;
- “the image has an SBOM”;
- “provenance exists”;
- “the artifact is signed”.

Those statements describe product presence or intent. They do not necessarily prove isolation, enforcement, attribution, containment, source completeness, artifact integrity, subject binding or trusted signer identity.

The design goal is simple:

> **Prove what can be proven, preserve the evidence, and make everything else visible.**

---

## What the project demonstrates

A customer PoC can use this repository to:

1. **Run a real coding task** inside a uniquely identified Docker Sandbox.
2. **Observe selected boundaries** through Docker `sbx` inventory, filesystem canaries and network-policy decisions.
3. **Assess all 35 draft Agent Baseline controls** without converting missing evidence into `PASS`.
4. **Analyze MCP governance posture** through Cedar-policy checks and optional Docker AI Governance audit metadata.
5. **Validate the agent-modified workspace**, not a separate static fixture.
6. **Preserve evidence integrity** with per-file SHA-256 manifests and a hash-chained normalized trace.
7. **Produce run attestations** and authenticate selected handoff artifacts with Ed25519 signatures.
8. **Exercise response semantics** with a disposable sandbox-scoped credential binding and verified postconditions.
9. **Build the resulting workspace with Docker Buildx** using SBOM and provenance attestations.
10. **Independently verify the OCI graph**, including manifests, config, binary layers, descriptor digest/size and duplicate-member ambiguity.
11. **Verify SPDX SBOM + SLSA provenance subject binding** instead of trusting artifact names.
12. **Optionally evaluate Docker Scout policy** in observe or fail-closed gate mode.
13. **Create agent → workspace → OCI artifact lineage** and invalidate it on later mutation.
14. **Generate a Customer Decision Brief** using `BLOCKED`, `CONDITIONAL` or `EVIDENCE_READY` rather than a synthetic score.
15. **Export governance findings as SARIF 2.1.0** for standard security-tool ingestion.
16. **Create a privacy-safe signed customer trust handoff** with nested verification and no private key or OCI binary archive.
17. **Compare two verified runs** control-by-control through Governance Delta.
18. **Fail closed on causal interpretation** when a before/after pair is not sufficiently controlled.

### Evidence statuses

Every Agent Baseline control is one of:

`PASS` · `FAIL` · `PARTIAL` · `MANUAL` · `N/A` · `ERROR`

A skipped live probe is never counted as a pass.

### Evidence classes

| Class | Meaning |
|---|---|
| **Declared** | configuration and design intent |
| **Observed** | runtime state, policy decisions and postconditions actually collected |
| **Linked** | artifacts correlated by stable identifiers or cryptographic digests |
| **Externally anchored** | evidence authenticated against material outside the artifact being verified |

---

## 60-second safe tour

Clone the repository and exercise the complete orchestration contract without mutating Docker state:

```bash
git clone https://github.com/riccardomenegazzo/agent-baseline-evidence-lab.git
cd agent-baseline-evidence-lab
make install
make signing-keygen
python -m agent_baseline_lab.customer_trust_flow \
  --profile community \
  --dry-run \
  --scout-mode off
```

Dry-run is intentionally fail-closed. It cannot claim live containment, credential revocation, runtime enforcement, SBOM/provenance generation or positive agent-to-artifact lineage. The dedicated `customer-trust` GitHub Actions workflow continuously tests that contract and independently re-verifies the generated handoff.

For the non-technical project summary, start with [`docs/EXECUTIVE_OVERVIEW.md`](docs/EXECUTIVE_OVERVIEW.md).

For the concise walkthrough, use [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md).

---

## Live customer trust flow

A live run requires a suitable Docker environment and the relevant Docker Sandboxes authentication/configuration.

Prepare the signed baseline and local signing identity:

```bash
make baseline-sync
make signing-keygen
make baseline-lock-verify
make baseline-lock-sign
make baseline-lock-verify-signature
```

### Observe mode

Use this for an exploratory/customer PoC where Scout findings should remain visible but are not yet an authorization gate:

```bash
python -m agent_baseline_lab.customer_trust_flow \
  --profile community \
  --scout-mode observe
```

### Strict gate mode

Make the configured Docker Scout policy part of the acceptance gate:

```bash
python -m agent_baseline_lab.customer_trust_flow \
  --profile community \
  --scout-mode gate
```

A non-passing Scout result prevents `EVIDENCE_READY` in gate mode.

### MCP-focused mode

```bash
python -m agent_baseline_lab.customer_trust_flow \
  --profile mcp \
  --scout-mode observe
```

Docker AI Governance audit evidence remains optional and is promoted to observed evidence only when finalized local records are actually available.

---

## Trusted software-supply-chain evidence

The trusted-artifact stage builds the exact agent workspace through a disposable `docker-container` Buildx builder and requests:

```text
--sbom=true
--provenance=mode=max
--output type=oci
```

The verifier does **not** accept “files with convincing names” as proof. It inspects the OCI representation itself.

It checks:

- top-level OCI descriptor digest and size;
- runnable image manifest integrity;
- attestation manifest integrity;
- referenced config blobs;
- referenced binary layers using streaming SHA-256;
- unsafe/duplicate archive member ambiguity;
- in-toto statement type;
- SPDX predicate presence;
- SLSA provenance predicate presence;
- attestation subject binding to the runnable image manifest.

The Dockerfile contract separately records:

- final non-root `USER` posture;
- external base-image references;
- digest pinning/reproducibility posture;
- runtime `HEALTHCHECK` declaration.

Docker Scout is an additional policy signal, not a substitute for the independent OCI verifier.

---

## Customer Decision Brief

The project deliberately avoids a composite “95/100 secure” score.

It emits one evidence disposition:

| Decision | Meaning |
|---|---|
| `BLOCKED` | a blocking check failed or required evidence is missing |
| `CONDITIONAL` | no blocker, but material gaps/findings require review |
| `EVIDENCE_READY` | evidence required by the selected PoC mode was observed and verified |

`EVIDENCE_READY` means **ready for the next human/organizational decision**. It does not mean “production approved”.

---

## Signed customer trust handoff

The final handoff can contain:

```text
customer-trust-handoff.zip
├── handoff-manifest.json
├── governance/
│   └── golden-flow.json
├── evidence/
│   ├── customer-evidence-pack.zip
│   └── customer-evidence-pack.zip.ed25519.json
├── trust/
│   └── attestation-public.json
├── supply-chain/
│   ├── trusted-artifact.json
│   ├── trusted-artifact.ed25519.json
│   └── optional Scout / BuildKit evidence
├── lineage/
│   ├── agent-artifact-lineage.json
│   └── agent-artifact-lineage.ed25519.json
├── decision/
│   ├── customer-decision.json
│   ├── customer-decision.html
│   └── customer-decision.ed25519.json
├── integrations/
│   └── agent-governance.sarif
└── customer-trust-flow.html
```

The pack verifier checks its own manifest/digests, verifies the nested customer evidence pack, verifies nested signatures when present, and rejects unsafe/unmanifested content.

It explicitly excludes:

- private signing keys;
- raw agent prompt/stdout/stderr;
- host filesystem paths;
- Docker credentials/local Docker state;
- OCI image archive and binary layers;
- unrelated local `.abl` state.

The final handoff ZIP is itself signed.

---

## Optional Docker MCP / AI Governance path

Register Docker's public DHI MCP endpoint:

```bash
make mcp-register-dhi
```

Observe registration and OAuth metadata without persisting token material:

```bash
make mcp-inventory-dhi
make mcp-oauth-status
```

With a live sandbox, probe whether direct network egress could bypass the intended host-side MCP path:

```bash
make mcp-bypass-dhi SANDBOX=<sandbox-name>
```

Run the MCP-focused live path:

```bash
make live-demo-mcp
```

Static policy analysis remains **policy evidence**, not proof of runtime enforcement.

---

## Independent verification

After an assessment:

```bash
make verify
make assurance-latest
```

`abl verify` checks that:

1. every manifested evidence file still matches its SHA-256 digest;
2. each normalized trace event links to the previous event hash;
3. the final trace hash and event count match the anchors in the assessment.

The assurance suite adds integrity/authenticity regression checks, signature verification, drift signals and response/incident evidence when available.

Its semantics remain separate from the control assessment:

- `PASS` — executed verification succeeded;
- `FAIL` — a blocking integrity/authenticity check failed;
- `FINDING` — a non-blocking risk signal requires review;
- `NOT_RUN` — optional evidence was unavailable.

---

## Before / after governance evidence

### Governance Delta — what changed?

```bash
make governance-delta \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>

make governance-delta-verify \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

The delta classifies control improvement/regression, evidence gain/loss, evaluator recovery/error, scope change and unchanged controls. It does **not** compute a security score.

### Controlled Experiment Protocol — can we discuss causality?

```bash
make experiment-protocol \
  BEFORE=evidence/abl-<before> \
  AFTER=evidence/abl-<after>
```

The protocol checks measured invariants such as baseline version, agent identity, task identity/digest, initial workspace digest, agent runtime and Docker Sandbox runtime fingerprint while separately fingerprinting the declared governance treatment.

It returns:

- `ELIGIBLE` — required measured invariants match and the treatment differs;
- `NOT_ELIGIBLE` — a required invariant differs, or no treatment change occurred;
- `INSUFFICIENT_EVIDENCE` — a required invariant cannot be established.

`ELIGIBLE` is not proof of causality. See [`docs/CONTROLLED_EXPERIMENT.md`](docs/CONTROLLED_EXPERIMENT.md).

---

## What gets produced

```text
agent-runs/
└── agent-<timestamp>-<id>/
    ├── session.json
    ├── workspace-before.json
    ├── workspace-after.json
    ├── workspace-changes.json
    ├── docker-observations.json
    └── manifest.sha256.json

evidence/
└── abl-<timestamp>/
    ├── inputs/
    ├── controls/
    ├── observations/
    ├── trace/events.ndjson
    ├── assessment.json
    └── manifest.sha256.json

reports/
├── abl-<timestamp>.json
├── abl-<timestamp>.html
├── abl-<timestamp>.attestation.json
├── assurance-summary.json
├── abl-<timestamp>.trust/
│   ├── trusted-artifact/
│   ├── trusted-artifact.portable.json
│   ├── agent-artifact-lineage.json
│   ├── customer-decision.portable.json
│   ├── customer-decision.portable.html
│   ├── agent-governance.sarif
│   └── customer-trust-flow.html
├── abl-<timestamp>.customer-trust-handoff.zip
├── governance-delta.json
├── controlled-experiment.json
└── governance-comparison-pack.zip
```

Raw prompts and raw agent output are not persisted by default.

---

## Claims the project deliberately refuses

The lab does **not** assume that:

- `Docker Sandbox installed → isolation control solved`;
- `MCP Gateway present → authorization solved`;
- `policy file exists → enforcement proven`;
- `audit logs exist → end-to-end attribution proven`;
- `sbx stop returned 0 → containment proven`;
- `credential binding removed → upstream provider token revoked`;
- `SBOM file exists → it belongs to this image`;
- `provenance file exists → its subject binding is valid`;
- `Scout present → every supply-chain control is satisfied`;
- `signature verifies → signer identity is trusted`;
- `hash chain verifies → source telemetry was complete`;
- `agent run + image exist → the agent produced that image`;
- `before/after improved → governance treatment caused the improvement`.

These distinctions are documented in [`docs/CLAIMS_BOUNDARY.md`](docs/CLAIMS_BOUNDARY.md).

---

## Download a release

The recommended distribution channel is [GitHub Releases](https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/releases/latest).

Each automated release publishes:

- an installable Python wheel;
- a source distribution;
- `SHA256SUMS`;
- `release-manifest.json` binding artifact digests to the source commit.

See [`DOWNLOAD.md`](DOWNLOAD.md).

---

## Documentation map

- **Executive / recruiting / leadership:** [`docs/EXECUTIVE_OVERVIEW.md`](docs/EXECUTIVE_OVERVIEW.md)
- **End-to-end customer trust chain:** [`docs/CUSTOMER_TRUST_FLOW.md`](docs/CUSTOMER_TRUST_FLOW.md)
- **Customer PoC:** [`docs/CUSTOMER_POC.md`](docs/CUSTOMER_POC.md)
- **Demo walkthrough:** [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md)
- **Architecture:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Control coverage:** [`docs/CONTROL_COVERAGE.md`](docs/CONTROL_COVERAGE.md)
- **Evidence model:** [`docs/EVIDENCE_MODEL.md`](docs/EVIDENCE_MODEL.md)
- **Docker evidence sources:** [`docs/DOCKER_EVIDENCE_SOURCES.md`](docs/DOCKER_EVIDENCE_SOURCES.md)
- **Governance Delta:** [`docs/GOVERNANCE_DELTA.md`](docs/GOVERNANCE_DELTA.md)
- **Controlled Experiment Protocol:** [`docs/CONTROLLED_EXPERIMENT.md`](docs/CONTROLLED_EXPERIMENT.md)
- **Response evidence:** [`docs/RESPONSE_DRILL.md`](docs/RESPONSE_DRILL.md)
- **Claims boundary:** [`docs/CLAIMS_BOUNDARY.md`](docs/CLAIMS_BOUNDARY.md)
- **Roadmap:** [`docs/ROADMAP.md`](docs/ROADMAP.md)

---

## Development and CI

```bash
make install
make test
make lint
make golden-demo-dry-run
```

Two independent GitHub Actions workflows protect the project:

- `ci` exercises package build, CLI entrypoints, framework tests, sample application tests, offline assessment, evidence verification, adversarial verifier regression, response semantics, signing, Governance Delta, comparison handoff, privacy boundaries, assurance and Golden Flow;
- `customer-trust` exercises the complete fail-closed Customer Trust Flow, verifies its signed handoff independently and asserts that dry-run cannot manufacture live lineage/trust claims.

The release workflow publishes only after the main CI succeeds. It builds wheel + source distribution, generates SHA-256 release metadata and smoke-tests the wheel in a clean environment.

---

## Project status

The repository is an **implementation, assurance and customer-PoC lab**, not a finished enterprise governance product.

The current main branch includes:

- all 35 Agent Baseline draft controls with explicit evidence semantics;
- Docker Sandbox runtime probes and bounded adversarial scenarios;
- MCP policy analysis and optional Docker AI Governance audit ingestion;
- privacy-minimized evidence and trace generation;
- run attestations and Ed25519 signing;
- response, quarantine and incident evidence;
- portable customer evidence packs;
- Governance Delta before/after comparison;
- Controlled Experiment Protocol;
- Docker Buildx SBOM/provenance trusted-artifact path;
- recursive OCI graph integrity verification;
- Docker Scout observe/gate integration;
- agent → artifact lineage;
- Customer Decision Brief;
- SARIF export;
- signed privacy-safe Customer Trust Handoff;
- dedicated end-to-end trust workflow in CI;
- automated downloadable releases.

Remaining work is intentionally focused on stronger **live** evidence and external trust anchors where the surrounding Docker/provider environment exposes trustworthy postconditions — not on manufacturing green results for unavailable signals.

See [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## License

Apache-2.0 for this repository's code. Agent Baseline materials remain under their upstream licenses and ownership; authoritative control requirement prose is not silently vendored here.
