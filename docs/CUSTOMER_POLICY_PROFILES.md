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

## Built-in profiles

The release wheel contains two deliberately different example profiles:

- `builtin:poc-observe` — permits `CONDITIONAL` or `EVIDENCE_READY`, requires a verified artifact and
  passing independent assurance, and forbids `FAIL`/`ERROR`;
- `builtin:enterprise-strict` — requires `EVIDENCE_READY`, verified artifact, Docker Scout `PASS`,
  assurance `PASS`, and zero `FAIL`/`ERROR`/`PARTIAL`/`MANUAL`.

They are examples, not Docker recommendations or compliance standards.

List or export them from any installed wheel:

```bash
abl-policy list-profiles
abl-policy export-profile enterprise-strict --output customer-policy.yaml
```

The repository also keeps readable copies under `policies/customer-trust/`.

## Evaluate

A built-in profile can be used without exporting it:

```bash
abl-policy evaluate \
  builtin:enterprise-strict \
  reports/<run-id>.trust/customer-decision.portable.json \
  --output reports/<run-id>.trust/customer-policy-evaluation.json
```

Or use an explicit customer-owned YAML file instead of `builtin:<name>`.

Exit code is non-zero when the supplied decision does not satisfy the profile.

The output binds the result to the canonical parsed policy with `profile_sha256`, so changing a
threshold or allowed state changes the policy identity even if the filename and version string are
left unchanged.

## Verify offline

```bash
abl-policy verify \
  reports/<run-id>.trust/customer-policy-evaluation.json \
  builtin:enterprise-strict \
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
lists, unsupported built-in names, and unsupported schema versions fail closed.

## Claims boundary

A passing profile evaluation means only that the supplied Customer Decision Brief satisfies the
exact versioned policy. It does not recreate the underlying Docker execution, prove external signer
identity, certify the workload, or authorize production deployment.
