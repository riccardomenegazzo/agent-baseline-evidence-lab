# Customer Acceptance Envelope

The Customer Trust Handoff is deliberately **policy-neutral**. It records portable evidence and its
verification material without assuming that every customer has the same acceptance threshold.

The Customer Acceptance Envelope adds a customer-specific layer without rewriting that evidence:

```text
verified Customer Trust Handoff
              +
versioned customer policy
              ↓
recomputed policy evaluation
              ↓
signed acceptance statement
              ↓
signed Customer Acceptance Envelope
```

This separation lets two customers evaluate the exact same evidence handoff against different
requirements while preserving the original handoff digest.

## Create an envelope

First produce a signed Customer Trust Handoff with `abl-trust`. Then select an explicit policy:

```bash
abl-accept create \
  --handoff reports/<run-id>.customer-trust-handoff.zip \
  --handoff-signature reports/<run-id>.customer-trust-handoff.zip.ed25519.json \
  --policy policies/customer-trust/enterprise-strict.yaml \
  --output reports/<run-id>.customer-acceptance-envelope.zip
```

By default the command uses the local Agent Baseline Evidence Lab Ed25519 keypair under `.abl/keys/`.
Creation fails closed when:

- the source handoff does not verify;
- its signature does not verify against the supplied public key;
- the handoff does not contain the customer decision role;
- the selected customer policy does not evaluate to `PASS`;
- the generated policy evaluation or acceptance statement cannot be verified after signing;
- the finished envelope cannot verify itself.

A failed policy does **not** modify or relabel the original Customer Decision Brief. Use
`abl-policy evaluate` when the goal is to inspect why a policy is not satisfied.

## Envelope contents

The deterministic-member ZIP contains:

- the original Customer Trust Handoff;
- its Ed25519 signature;
- the public verification key;
- the exact customer policy YAML;
- a recomputable customer policy evaluation;
- the evaluation signature;
- an acceptance statement binding the handoff digest, decision digest, policy digest and evaluation
  digest;
- the acceptance-statement signature;
- an `acceptance-manifest.json` covering every packaged member.

The ZIP itself is also signed as a separate `.ed25519.json` artifact.

## Verify offline

```bash
abl-accept verify \
  reports/<run-id>.customer-acceptance-envelope.zip \
  --signature reports/<run-id>.customer-acceptance-envelope.zip.ed25519.json
```

Verification independently checks:

1. ZIP path/member integrity and manifest digests/sizes;
2. the nested Customer Trust Handoff;
3. the nested handoff signature;
4. extraction of the customer decision from the handoff by semantic role;
5. recomputation of the customer policy evaluation;
6. the policy-evaluation signature;
7. the acceptance statement's handoff, decision, policy and evaluation bindings;
8. the acceptance-statement signature;
9. manifest identity fields; and
10. the outer envelope signature when supplied.

## Why the envelope is separate

A customer acceptance policy is not observed security evidence. Embedding one customer's thresholds
inside the generic evidence handoff would make the handoff less reusable and could blur the boundary
between **what happened** and **what a specific organization is willing to accept**.

The envelope keeps those concepts distinct:

- **Customer Trust Handoff:** portable evidence and verification material.
- **Customer Policy Profile:** explicit acceptance criteria.
- **Customer Acceptance Envelope:** cryptographic binding between the two when the policy passes.

## Claims boundary

`PASS` means only that the included verified Customer Decision Brief satisfies the exact included
policy. It is not a synthetic security score, production authorization, external signer-identity
proof, official Docker certification, or compliance certification.
