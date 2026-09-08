# Customer Trust Flow

The Customer Trust Flow is the highest-level PoC lifecycle in Agent Baseline Evidence Lab. It connects one AI coding-agent execution to governance evidence, a trusted container build, software-supply-chain attestations, a decision artifact and a signed customer handoff.

It is designed as a reusable CXE / TAM / solution-architecture pattern rather than a product showcase.

> Community project. This flow does not issue Docker certification, compliance certification or production authorization.

## The question it answers

An enterprise adopting coding agents may have all of the following at the same time:

- an isolated execution environment;
- network and MCP controls;
- an agent that changes application code;
- a container build pipeline;
- SBOM and provenance generation;
- vulnerability and policy tooling.

The hard question is whether those observations can be linked into one defensible statement:

> **Did this governed agent run produce the workspace from which this exact container artifact was built, and what evidence supports that claim?**

The flow therefore treats trust as a chain rather than as a feature checklist.

```text
AI coding task
      │
      ▼
Docker Sandbox / governed execution
      │
      ▼
Agent-run capsule
      ├── task digest
      ├── execution metadata
      ├── workspace-before digest
      └── workspace-after digest
      │
      ▼
Agent Baseline assessment
      ├── evidence bundle
      ├── hash-chained trace
      ├── run attestation
      └── independent assurance
      │
      ▼
Docker Buildx
      ├── OCI artifact
      ├── SPDX SBOM
      └── SLSA provenance
      │
      ▼
Independent OCI verification
      ├── descriptor digest + size
      ├── manifest/config/layer graph
      ├── attestation statements
      └── image subject binding
      │
      ├── optional Docker Scout policy / CVE evidence
      │
      ▼
Agent → workspace → artifact lineage
      │
      ▼
Customer Decision Brief + SARIF
      │
      ▼
Signed customer trust handoff
```

## Trust gates

A positive live lineage is created only when all of these are true:

1. the selected agent-run evidence manifest verifies;
2. the trusted build context is the workspace recorded by that agent run;
3. the current workspace SHA-256 matches the recorded post-task workspace snapshot;
4. the trusted-artifact report is `VERIFIED`;
5. the OCI archive digest matches the trusted-artifact report;
6. the complete referenced OCI graph verifies recursively;
7. SPDX SBOM evidence is present;
8. SLSA provenance evidence is present;
9. the attestation statements are bound to the referred runnable image manifest.

Any change to the workspace or OCI archive after those observations invalidates the lineage.

## Modes

### Dry-run

```bash
python -m agent_baseline_lab.customer_trust_flow \
  --profile community \
  --dry-run \
  --scout-mode off
```

Dry-run is a contract test for orchestration and packaging. It deliberately does **not**:

- invoke a live coding agent;
- claim sandbox containment;
- build an OCI artifact;
- claim SBOM/provenance generation;
- create positive agent-to-artifact lineage;
- evaluate Docker Scout.

Its final disposition is `DRY_RUN`, never `EVIDENCE_READY`.

### Observe

```bash
python -m agent_baseline_lab.customer_trust_flow \
  --profile community \
  --scout-mode observe
```

This is the preferred exploratory/customer PoC mode. The trusted-artifact chain must verify, while Docker Scout is reported transparently but is not by itself a release gate.

This is useful where:

- Scout is not configured for the environment;
- policy configuration is still being agreed with the customer;
- the purpose is evidence discovery rather than deployment authorization.

### Gate

```bash
python -m agent_baseline_lab.customer_trust_flow \
  --profile community \
  --scout-mode gate
```

Gate mode makes the configured Docker Scout policy a required part of the final evidence disposition. A non-passing Scout result prevents `EVIDENCE_READY`.

The supplied Scout policy profile is intentionally narrow and reviewable. It focuses on supply-chain attestations, approved base-image posture and fixable Critical/High vulnerabilities. Customers should treat it as a PoC policy starting point, not a universal production policy.

## MCP-focused path

For an MCP-oriented run:

```bash
python -m agent_baseline_lab.customer_trust_flow \
  --profile mcp \
  --scout-mode observe
```

The MCP profile reuses the same trust lifecycle while adding the MCP-specific evidence sources already supported by the repository. Docker AI Governance audit evidence remains optional and is only promoted to observed evidence when finalized local audit records are actually available.

## Signing prerequisites

The flow requires a local Ed25519 key pair:

```bash
make signing-keygen
```

For a live golden flow, synchronize and sign the Agent Baseline lock first:

```bash
make baseline-sync
make baseline-lock-verify
make baseline-lock-sign
make baseline-lock-verify-signature
```

A valid Ed25519 signature proves possession of the configured private key. It does **not** prove organizational identity unless the public key is anchored through an independent identity/trust process.

## Trusted artifact verification

The software-supply-chain stage does not accept file names such as `sbom.json` as evidence by themselves.

It verifies the OCI representation produced by BuildKit:

- top-level index descriptors;
- runnable image manifest;
- attestation manifest;
- referenced config blobs;
- referenced binary layers;
- descriptor SHA-256 values;
- descriptor sizes;
- duplicate-member ambiguity;
- SPDX in-toto predicate;
- SLSA provenance predicate;
- subject binding from attestation to runnable image manifest.

The OCI archive itself stays local and is intentionally excluded from the portable customer handoff. The handoff carries its SHA-256 and the verified findings instead.

## Decision semantics

The Customer Decision Brief deliberately avoids a composite security score.

It emits one of:

| Decision | Meaning |
|---|---|
| `BLOCKED` | blocking evidence failed or a required trust gate is missing |
| `CONDITIONAL` | no blocking failure, but material evidence gaps/findings remain |
| `EVIDENCE_READY` | all evidence required by the selected PoC mode was observed and verified |

`EVIDENCE_READY` means the evidence package is ready for the next human/organizational decision. It does not mean “approved for production”.

## Customer trust handoff

The final ZIP is independently manifested and can contain:

- golden-flow summary;
- portable customer evidence pack;
- signature of that evidence pack;
- public verification key;
- portable trusted-artifact report;
- signature of the trusted-artifact report;
- agent→artifact lineage statement and signature for live verified runs;
- Customer Decision Brief in JSON/HTML;
- decision signature;
- Agent Baseline + supply-chain SARIF;
- optional portable BuildKit metadata;
- optional Docker Scout result/report/SARIF;
- visual Customer Trust Flow summary.

The handoff explicitly excludes:

- private signing keys;
- raw agent prompts and raw stdout/stderr;
- host filesystem paths;
- Docker credentials/local Docker state;
- the OCI binary image archive;
- unrelated local `.abl` state.

Its verifier checks:

- ZIP member uniqueness;
- safe archive paths;
- per-member SHA-256 and size;
- absence of unmanifested content;
- forbidden material boundaries;
- the embedded customer evidence pack;
- the embedded customer-pack signature when present;
- the embedded lineage signature when present.

The final handoff ZIP is then itself signed.

## Machine-readable integration

The flow exports SARIF 2.1.0 so governance and supply-chain findings can be consumed by standard security tooling.

Mapping is intentionally conservative:

```text
FAIL / ERROR  -> error
PARTIAL       -> warning
FINDING       -> warning
MANUAL        -> note
PASS          -> omitted
```

This keeps the integration useful without converting absence of findings into a compliance claim.

## Why this is a reusable customer PoC

The flow separates five concerns that are often conflated:

1. **Execution** — what the agent was allowed to do.
2. **Observation** — what was actually recorded during this run.
3. **Artifact trust** — what can be verified about the produced container.
4. **Lineage** — whether the observed agent workspace and the trusted artifact are cryptographically linked.
5. **Decision** — whether the evidence is sufficient for the selected PoC acceptance criteria.

That separation lets a customer change policy thresholds, agent type, MCP profile or Docker environment without changing the core evidence model.

## Recommended demo narrative

A concise manager/customer demonstration should show:

1. the problem statement rather than code first;
2. one agent task;
3. the post-task workspace digest;
4. Buildx SBOM/provenance generation;
5. OCI graph/attestation verification;
6. the agent→artifact lineage statement;
7. the Decision Brief;
8. the signed portable handoff;
9. one deliberate mutation showing that verification fails.

The strongest message is not that many controls exist. It is that **each positive claim has a defined source of evidence, a verifier and a failure mode**.
