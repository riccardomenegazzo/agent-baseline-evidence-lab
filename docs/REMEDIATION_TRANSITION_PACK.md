# Verified Remediation Transition Pack

The remediation transition pack combines two before/after evidence planes without collapsing them into one claim:

1. **governance transition** — the existing signed governance comparison pack, including the recomputable Governance Delta;
2. **artifact transition** — the signed deterministic OCI Artifact Diff, plus the exact trusted-artifact reports used to build it.

The pack is designed for a customer handoff after a remediation, hardening change, base-image migration, or other controlled technical transition.

## Why two evidence planes

A control can improve without changing the runnable image. An image can change without explaining why a governance control improved. A provenance material can move while the runnable OCI graph remains stable.

For that reason the transition pack never treats governance change and artifact change as interchangeable evidence and never infers causality from their co-occurrence.

## Create

```bash
abl-transition create \
  evidence/abl-before \
  evidence/abl-after \
  reports/before-trusted-artifact.json \
  reports/after-trusted-artifact.json \
  --output reports/remediation-transition.zip
```

Creation requires the local Ed25519 keypair used by the other signed handoff flows.

## Portable verification

A recipient can verify the pack without receiving the OCI layer archives:

```bash
abl-transition verify \
  reports/remediation-transition.zip \
  --signature reports/remediation-transition.zip.ed25519.json \
  --public .abl/keys/attestation-public.json
```

Portable verification checks:

- deterministic member inventory, SHA-256 and size binding;
- no duplicate or unsafe ZIP member paths;
- no private signing key in the handoff;
- the nested governance comparison pack and its signature;
- continuity between the nested comparison public key and the transition public key;
- the OCI Artifact Diff signature;
- SHA-256 binding from the signed diff to both embedded trusted-artifact reports;
- transition manifest binding to before/after run IDs and artifact classification;
- optional outer-pack signature verification.

Portable verification does **not** independently replay the OCI graph because the potentially large OCI archives are deliberately not copied into the customer handoff.

## Full OCI recomputation

When the original trusted-artifact reports and their referenced OCI archives are available locally, the same verifier can replay the artifact comparison:

```bash
abl-transition verify \
  reports/remediation-transition.zip \
  --signature reports/remediation-transition.zip.ed25519.json \
  --public .abl/keys/attestation-public.json \
  --before-trusted-artifact reports/before-trusted-artifact.json \
  --after-trusted-artifact reports/after-trusted-artifact.json \
  --root .
```

The verifier first requires the supplied reports to be byte-identical to the reports embedded in the transition pack. It then invokes the OCI Artifact Diff verifier, which re-checks each report-to-archive SHA-256 binding, recursive OCI graph integrity, Docker attestation structure, SBOM/provenance presence and subject binding before reconstructing the diff.

Both `--before-trusted-artifact` and `--after-trusted-artifact` are required when full recomputation is requested.

## Pack layout

```text
transition-manifest.json
governance/
  comparison-pack.zip
  comparison-pack.zip.ed25519.json
artifact/
  oci-artifact-diff.json
  oci-artifact-diff.html
  oci-artifact-diff.json.ed25519.json
  before-trusted-artifact.json
  after-trusted-artifact.json
trust/
  attestation-public.json
```

The OCI archives themselves are excluded by design.

## Verification model

The transition handoff has three distinct verification levels:

- **structural integrity** — manifest, member digests, safe paths and duplicate rejection;
- **portable cryptographic verification** — governance comparison signature, artifact-diff signature, source-report bindings and optional outer signature;
- **full source recomputation** — all of the above plus independent OCI graph and attestation replay from the original archives.

The embedded key proves only continuity of the local signing key. External organizational identity requires a separately trusted identity or key-distribution mechanism.

## Claims boundary

A verified transition pack proves that the included governance and artifact transition evidence is internally bound to the signed handoff and, when full recomputation is used, that the artifact diff can be reconstructed from the supplied trusted-artifact reports and their OCI archives.

It does not prove that one transition caused the other, that the remediation is complete, that telemetry is complete, that the signer represents a particular organization, that the image is vulnerability-free, that behavior is equivalent, or that deployment is authorized.
