# Agent Run Attestation

Agent Baseline Evidence Lab v0.5 emits an **unsigned in-toto-style Statement** for every assessment.

The goal is not to claim certification or introduce a private conformance format. The goal is to bind the evidence-manifest digest to the execution facts that the lab actually observed, while making the trust boundary explicit.

## Why this exists

A SHA-256 file manifest and a hash-chained trace can prove that an exported bundle is internally self-consistent. They cannot, by themselves, prove who produced that bundle: an actor able to rewrite every file can recompute every internal hash.

The run attestation therefore separates:

1. **bundle consistency** — `abl verify`;
2. **statement-to-manifest binding** — `abl verify-attestation`;
3. **authenticity** — requires an externally pinned attestation digest today, and could use a cryptographic signer in a future version.

This distinction is directly relevant to the implementation concern discussed in `agentbaseline/agentbaseline#26` around independently verifiable evidence.

## Statement shape

Each assessment produces:

```text
reports/abl-<timestamp>.attestation.json
```

The statement uses:

```text
_type: https://in-toto.io/Statement/v1
```

with a project-specific predicate type. Its single subject is the run's `manifest.sha256.json`.

The predicate binds the manifest to:

- Agent Baseline version;
- assessment run ID and timestamps;
- exact assessment-config SHA-256;
- final trace-head SHA-256 and event count;
- digest of the 35-control result vector;
- coding-agent session ID;
- Docker Sandbox identity;
- task digest and size without persisting the raw prompt;
- agent stdout/stderr digests without persisting output by default;
- workspace root digest before and after the task;
- digest of the changed-path set; and
- Docker AI Governance audit summary when present.

## Verify

After an assessment:

```bash
run_id=abl-...

abl verify-attestation \
  "reports/${run_id}.attestation.json" \
  "evidence/${run_id}/manifest.sha256.json"
```

That verifies statement shape and subject binding.

For an externally anchored check:

```bash
abl verify-attestation \
  "reports/${run_id}.attestation.json" \
  "evidence/${run_id}/manifest.sha256.json" \
  --expected-attestation-sha256 <sha256-pinned-elsewhere>
```

The external digest might be stored in a CI log, ticket, transparency service or another system outside the evidence producer's control.

## Negative test

The unit suite deliberately mutates the evidence manifest after attestation creation and asserts that verification fails.

This is important: the implementation demonstrates the failure path rather than only testing valid statements.

## Claim boundary

The current statement records:

```text
signed: false
externalTrustAnchorRequiredForAuthenticity: true
```

Do not describe the v0.5 attestation as a digital signature, certification or proof of official Agent Baseline conformance.

A future signing backend should be additive: the unsigned statement format and evidence-manifest binding can remain stable while a signer or transparency mechanism establishes origin authenticity.
