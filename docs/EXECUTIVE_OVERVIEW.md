# Executive Overview

## What problem does this project address?

AI coding agents can modify source code, invoke tools, reach networks and produce software artifacts. Enterprise teams therefore need more than a statement that an agent is “sandboxed” or that an image has an SBOM: they need evidence showing what actually happened, what artifact was produced, what can be independently verified, and what still remains unproven.

**Agent Baseline Evidence Lab** is a community reference PoC for that problem.

It uses the Agent Baseline v1.0-draft as a governance vocabulary and Docker Sandboxes as the primary execution surface, then extends the evidence chain through Docker Buildx, OCI SBOM/provenance attestations, optional Docker Scout policy evaluation, agent-to-artifact lineage and a signed customer handoff.

> Community project. It is not an official Docker or Agent Baseline product, certification or conformance program.

---

## The core idea

Instead of producing a single security score, every run asks:

> **For this agent, in this environment, during this run: what can we actually prove — and can we link that evidence to the exact container artifact the agent produced?**

The strongest project path is the **Customer Trust Flow**:

```text
AI coding task
   ↓
Docker Sandbox / governed execution
   ↓
Agent Baseline assessment + assurance
   ↓
agent-modified workspace
   ↓
Docker Buildx OCI artifact
   ├─ SBOM
   └─ provenance
   ↓
OCI graph + attestation verification
   ↓
optional Docker Scout policy evidence
   ↓
agent → workspace → artifact lineage
   ↓
Customer Decision Brief + SARIF
   ↓
signed privacy-safe customer trust handoff
```

Each stage has its own evidence source, verifier, failure semantics and claims boundary.

---

## What a customer can demonstrate

A representative PoC can show that a team can:

1. run a real coding task in a uniquely identified Docker Sandbox;
2. test selected runtime/network boundaries without destructive probes;
3. assess all 35 draft Agent Baseline controls without converting missing evidence into `PASS`;
4. independently verify the assessment evidence bundle and trace linkage;
5. build the exact agent-modified workspace with Docker Buildx;
6. verify the OCI graph rather than trusting an archive/file name;
7. verify SPDX SBOM and SLSA provenance **subject binding** to the runnable image;
8. collect Docker Scout evidence in informational `observe` mode or explicit `gate` mode;
9. cryptographically link the recorded post-agent workspace to the trusted image artifact;
10. produce an evidence-derived `BLOCKED`, `CONDITIONAL`, `EVIDENCE_READY` or `DRY_RUN` decision;
11. export findings as SARIF 2.1.0;
12. provide another reviewer with a signed, private-key-free and independently verifiable handoff;
13. compare two verified runs without inventing a security score;
14. reject uncontrolled before/after pairs as causal evidence.

---

## Why the evidence model matters

The project separates four evidence classes:

| Evidence class | Meaning |
|---|---|
| **Declared** | configuration and intended state |
| **Observed** | runtime state, decisions and postconditions actually collected |
| **Linked** | artifacts correlated by identifiers or cryptographic digests |
| **Externally anchored** | evidence authenticated against trust material outside the artifact being verified |

This prevents shortcuts such as:

```text
Docker Sandbox exists  != isolation fully proven
SBOM exists            != artifact secure
provenance exists      != code correct
Scout passes           != vulnerability-free or certified
lineage verifies       != workload behavior safe
signature verifies     != organizational identity
```

Unsupported claims remain visible instead of being converted into a green result.

---

## Customer decision semantics

The Customer Decision Brief deliberately avoids a composite “95/100 secure” score.

| Decision | Meaning |
|---|---|
| `BLOCKED` | a required trust condition failed |
| `CONDITIONAL` | useful evidence exists, but material gaps/findings remain |
| `EVIDENCE_READY` | the configured PoC evidence requirements were satisfied |
| `DRY_RUN` | orchestration was exercised without live trust claims |

`EVIDENCE_READY` means **ready for the next customer/organizational decision**, not production approval or Docker certification.

---

## What makes the PoC reusable

The repository is designed as a technical-enablement asset rather than a one-off demo:

- one installable `abl-trust` command for the complete lifecycle;
- `off / observe / gate` Scout policy semantics;
- configuration-driven assessment;
- explicit success criteria;
- offline-safe and live paths;
- machine-readable JSON and human-readable HTML;
- SARIF for existing security workflows;
- deterministic offline handoff verification;
- regression tests for evidence tampering and false-positive claims;
- separate community-accessible and optional Docker AI Governance paths;
- downloadable releases with checksums, source-bound manifests and GitHub/Sigstore-backed SLSA provenance.

---

## Two-minute safe review

```bash
make install
make customer-trust-dry-run
```

This exercises the complete orchestration and signed-handoff contract without mutating Docker state. Dry-run deliberately cannot manufacture live artifact lineage or runtime enforcement evidence.

For a live PoC after baseline/signing preparation:

```bash
make customer-trust SCOUT_MODE=observe
```

or:

```bash
abl-trust --scout-mode observe
```

---

## Where to look next

- [`CUSTOMER_TRUST_FLOW.md`](CUSTOMER_TRUST_FLOW.md) — end-to-end trust chain;
- [`CUSTOMER_POC.md`](CUSTOMER_POC.md) — measurable customer scenario and acceptance criteria;
- [`DEMO_GUIDE.md`](DEMO_GUIDE.md) — concise manager/customer walkthrough;
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — four-plane architecture;
- [`EVIDENCE_MODEL.md`](EVIDENCE_MODEL.md) — evidence and trust semantics;
- [`CLAIMS_BOUNDARY.md`](CLAIMS_BOUNDARY.md) — what the project deliberately refuses to claim;
- [`RELEASE_PROVENANCE.md`](RELEASE_PROVENANCE.md) — downloadable artifact provenance.

---

## Current maturity

The project is an implementation, assurance and customer-PoC lab, not a finished enterprise governance product.

Its value is the reference pattern: **turn recurring AI-agent governance questions into reusable PoCs with explicit success criteria, evidence, artifact lineage, policy semantics and independently verifiable customer handoffs.**
