# Customer Policy Profiles

Customer policy profiles let different customers evaluate the **same verified evidence handoff** against different acceptance requirements without rewriting the underlying evidence or manufacturing a synthetic security score.

The policy layer is deliberately separate from evidence collection:

```text
Docker / agent / assessment evidence
            |
            v
Customer Decision Brief
            |
            +-------------------------------+
            |                               |
            v                               v
      Customer policy A               Customer policy B
            |                               |
            v                               v
      Acceptance result A              Acceptance result B
```

A policy result says only whether the supplied evidence satisfies one exact, versioned policy. It is not production authorization, certification or proof that every relevant control was observed.

## Built-in profiles

The installed wheel ships three example profiles:

| Profile | Policy schema | Purpose |
|---|---:|---|
| `builtin:poc-observe` | 1 | Allows a bounded PoC to remain conditional while still forbidding assessment `FAIL`/`ERROR`. |
| `builtin:enterprise-strict` | 1 | Requires an evidence-ready decision, trusted artifact, Scout `PASS`, assurance `PASS` and no unresolved assessment status. |
| `builtin:enterprise-supply-chain` | 2 | Adds direct requirements over the trusted-artifact evidence, including runtime posture and verified OCI attestation facts. |

Discover or export them from an installed release:

```bash
abl-policy list-profiles
abl-policy export-profile enterprise-supply-chain --output customer-policy.yaml
```

Built-in profiles are examples, not Docker recommendations or compliance standards.

## Policy schema v1

Schema v1 evaluates fields already summarized by the Customer Decision Brief.

```yaml
schema_version: 1
id: enterprise-strict
version: 1.0.0
requirements:
  decision:
    allowed: [EVIDENCE_READY]
  trusted_artifact:
    allowed: [VERIFIED]
  docker_scout:
    allowed: [PASS]
  assurance:
    allowed: [PASS]
  max_assessment_counts:
    FAIL: 0
    ERROR: 0
    PARTIAL: 0
    MANUAL: 0
```

## Policy schema v2: artifact-aware acceptance

Schema v2 can additionally evaluate the actual `trusted-artifact.json` included in the signed Customer Trust Handoff.

```yaml
schema_version: 2
id: enterprise-supply-chain
version: 1.0.0
requirements:
  decision:
    allowed: [EVIDENCE_READY]
  trusted_artifact:
    allowed: [VERIFIED]
  docker_scout:
    allowed: [PASS]
  assurance:
    allowed: [PASS]
  max_assessment_counts:
    FAIL: 0
    ERROR: 0
    PARTIAL: 0
    MANUAL: 0
  trusted_artifact_checks:
    default-non-root-user:
      allowed: [PASS]
    runtime-healthcheck:
      allowed: [PASS]
    oci-attestation-integrity:
      allowed: [PASS]
  artifact_facts:
    sbom_present: true
    provenance_present: true
    subject_bindings_valid: true
```

The supported artifact facts are intentionally narrow and derived from the independent OCI verifier:

- `sbom_present` — an SPDX attestation predicate was observed;
- `provenance_present` — a SLSA provenance predicate was observed;
- `subject_bindings_valid` — observed attestation subjects match their referred runnable image manifest.

A schema-v2 policy that requires artifact evidence fails closed if the trusted artifact is missing, a required check is absent, a check ID is duplicated, or a required fact is unavailable.

## Evaluate evidence directly

```bash
abl-policy evaluate \
  builtin:enterprise-supply-chain \
  reports/customer-decision.json \
  --trusted-artifact reports/trusted-artifact.json \
  --output reports/customer-policy-evaluation.json
```

The evaluation contains:

- exact policy identity and version;
- canonical policy SHA-256;
- source assessment run ID;
- trusted-artifact SHA-256 for schema-v2 evaluations;
- one explicit `PASS`/`FAIL` check per requirement;
- a claims boundary.

The customer decision and trusted-artifact inputs are never rewritten to make the policy pass.

## Recompute and verify

```bash
abl-policy verify \
  reports/customer-policy-evaluation.json \
  builtin:enterprise-supply-chain \
  reports/customer-decision.json \
  --trusted-artifact reports/trusted-artifact.json
```

Verification recomputes the result from the supplied policy and evidence. Changing the trusted artifact after evaluation changes its digest and invalidates the result.

Legacy schema-v1 policy evaluations remain verifiable after upgrading the tool.

## Customer Acceptance Envelope

`abl-accept` evaluates the policy against evidence extracted from the already verified Customer Trust Handoff. For schema-v2 artifact-aware policies, it reads the `trusted-artifact` role from that handoff rather than trusting an unrelated external file.

```bash
abl-accept create \
  --handoff reports/<run-id>.customer-trust-handoff.zip \
  --handoff-signature reports/<run-id>.customer-trust-handoff.zip.ed25519.json \
  --policy builtin:enterprise-supply-chain \
  --output reports/customer-acceptance-envelope.zip
```

The v2 acceptance statement cryptographically binds:

```text
verified handoff digest
        +
customer decision digest
        +
trusted-artifact digest
        +
exact policy digest
        +
recomputed policy-evaluation digest
```

The policy evaluation and acceptance statement are signed, the final envelope is signed, and the verifier independently recomputes the policy before accepting the envelope.

## Failure semantics

The artifact-aware path deliberately fails rather than degrading evidence semantics when:

- the policy requests an unsupported requirement;
- a required trusted-artifact check is absent;
- the trusted artifact contains duplicate check IDs;
- SBOM/provenance/subject-binding facts cannot be derived;
- the policy evaluation no longer matches the evidence;
- the nested handoff or any signed acceptance component is tampered with.

This keeps customer-specific acceptance separate from the evidence itself: **policy can reject evidence, but policy cannot turn missing evidence into observed evidence.**
