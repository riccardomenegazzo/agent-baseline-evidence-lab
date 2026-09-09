# Verified OCI Artifact Diff

`abl-artifact-diff` creates deterministic, independently recomputable evidence about what changed between two **already verified** trusted OCI artifacts.

The design avoids a common comparison mistake:

> **Different `.tar` bytes do not necessarily mean a different runnable OCI graph.**

Tar member order, archive metadata or non-semantic attestation metadata can change while the modeled runnable image graph remains the same. The diff therefore keeps several identities separate instead of collapsing them into one digest.

## Required inputs

The command accepts two trusted-artifact JSON reports. Each report must:

- have `overall_status: VERIFIED`;
- identify an existing OCI archive;
- contain the exact SHA-256 of that archive.

Before comparison, each archive is independently re-verified with both the recursive OCI graph verifier and the attestation verifier. A stale report, mutated archive, malformed graph or invalid SBOM/provenance subject binding fails closed.

## Identity layers

For each artifact the snapshot records:

### Archive SHA-256

Byte identity of the complete OCI tar archive.

This intentionally changes when tar packaging changes.

### Runnable graph fingerprint

A canonical SHA-256 over the verified runnable image descriptors:

- platform;
- runnable manifest digest;
- config digest;
- ordered layer digests.

Tar member order and tar header metadata are excluded from this fingerprint.

### Supply-chain evidence fingerprint

A separate canonical SHA-256 over selected verified supply-chain facts:

- attestation predicate types;
- normalized SLSA provenance materials;
- SBOM presence;
- provenance presence;
- subject-binding validity.

Raw attestation statement digests are still recorded and diffed, but they are not allowed to turn a build invocation nonce or timestamp into a false runnable-image change.

### Declared base-image evidence

The diff carries forward the trusted-artifact report's observed Dockerfile base-image evidence:

- external base references;
- digest-pinned references;
- tag-only references.

These are kept separate from provenance materials. The tool does **not** infer that an arbitrary SLSA material is necessarily a base image.

## Classifications

| Classification | Meaning |
|---|---|
| `IDENTICAL` | Archive bytes and all modeled identities are unchanged. |
| `REPACKAGED_EQUIVALENT` | Archive bytes differ, but the modeled runnable graph, selected supply-chain fingerprint, declared base-image evidence and Scout status are unchanged. |
| `BUILD_EVIDENCE_CHANGED` | Runnable graph is unchanged, but provenance-material/predicate evidence, declared base-image evidence or Scout status changed. |
| `ARTIFACT_CHANGED` | The verified runnable OCI manifest/config/layer graph changed. |

`REPACKAGED_EQUIVALENT` is deliberately bounded: it means equivalent under the fields modeled by this verifier, not universal behavioral equivalence.

## Create a diff

```bash
abl-artifact-diff create \
  reports/before/trusted-artifact.json \
  reports/after/trusted-artifact.json \
  --output reports/oci-artifact-diff.json \
  --html reports/oci-artifact-diff.html
```

The JSON includes explicit added/removed sets for:

- runnable manifests;
- image configs;
- layers;
- attestation predicate types;
- raw attestation statement digests;
- provenance materials;
- declared base-image references.

When the same provenance material URI is present on both sides but its digest changes, the transition is also emitted as a dedicated `digest_changes` record.

## Verify a diff

```bash
abl-artifact-diff verify \
  reports/oci-artifact-diff.json \
  reports/before/trusted-artifact.json \
  reports/after/trusted-artifact.json
```

Verification re-reads both trusted-artifact reports, re-checks both archive digests, recursively re-verifies both OCI graphs and attestations, reconstructs both canonical snapshots and recomputes the full diff.

Changing the diff, either source report or either OCI archive invalidates verification.

## Why this matters for customer workflows

A customer remediation or hardening conversation often asks a stronger question than “did the digest change?” For example:

- did the runnable image really change, or was the OCI layout merely repackaged?
- which layer was added or removed?
- did the base-image declaration move from tag-only to digest-pinned?
- did a provenance material resolve to a new digest?
- did Scout status change even though the runnable graph did not?
- did an attestation statement change while the selected material identity stayed stable?

The artifact diff makes those differences explicit without pretending to know why they happened.

## Claims boundary

The diff is evidence of observed cryptographic and metadata transitions between two verified OCI artifacts. It does not prove causality, behavioral equivalence, vulnerability absence, deployment state, external signer identity or production suitability.

For causal before/after claims, use the separate [Controlled Experiment Protocol](CONTROLLED_EXPERIMENT.md), which applies its own invariant checks.
