# Customer policy profiles

Evidence and customer acceptance are intentionally separate concerns.

The Customer Trust Flow records what was observed and produces a `Customer Decision Brief`.
`abl-policy` answers a different question:

> **Does this already-produced evidence disposition satisfy this customer's exact acceptance policy?**

A policy profile never rewrites assessment results, Docker Scout findings, artifact evidence, or
assurance evidence. It is a versioned acceptance layer over the decision artifact.

## Why this matters

Different customers can evaluate the same evidence differently. An exploratory PoC may accept
`CONDITIONAL` evidence with documented gaps, while a production promotion policy may require
`EVIDENCE_READY`, a verified artifact, a passing Docker Scout policy result, and zero unresolved
manual or partial controls.

Keeping policy outside the evidence model prevents a customer-specific threshold from being
misrepresented as an observed security fact.

## Included examples

- `policies/customer-trust/poc-observe.yaml` — permits `CONDITIONAL` or `EVIDENCE_READY`,
  requires a verified artifact and passing independent assurance, and forbids `FAIL`/`ERROR`.
- `policies/customer-trust/enterprise-strict.yaml` — requires `EVIDENCE_READY`, verified artifact,
  Docker Scout `PASS`, assurance `PASS`, and zero `FAIL`/`ERROR`/`PARTIAL`/`MANUAL`.

These are examples, not Docker recommendations or compliance standards.

## Evaluate

```bash
abl-policy evaluate \
  policies/customer-trust/enterprise-strict.yaml \
  reports/<run-id>.trust/customer-decision.portable.json \
  --output reports/<run-id>.trust/customer-policy-evaluation.json
```

Exit code is non-zero when the supplied decision does not satisfy the profile.

The output binds the result to the canonical parsed policy with `profile_sha256`, so changing a
threshold or allowed state changes the policy identity even if the filename and version string are
left unchanged.

## Verify offline

```bash
abl-policy verify \
  reports/<run-id>.trust/customer-policy-evaluation.json \
  policies/customer-trust/enterprise-strict.yaml \
  reports/<run-id>.trust/customer-decision.portable.json
```

Verification recomputes all checks against both the decision and the supplied policy and rejects
changes to the recorded status, checks, profile digest, source run, or claims boundary.

## Supported requirements

```yaml
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

Unknown requirement names, unknown assessment statuses, negative thresholds, malformed allowed
lists, and unsupported schema versions fail closed.

## Claims boundary

A passing profile evaluation means only that the supplied Customer Decision Brief satisfies the
exact versioned policy. It does not recreate the underlying Docker execution, prove external signer
identity, certify the workload, or authorize production deployment.
