# Contributing

Contributions should improve either **the quality of evidence** or **the honesty and usability of an assessment**.

A larger feature surface is not automatically an improvement. Prefer a small evaluator with precise evidence semantics over a broad claim that cannot be independently checked.

## Development setup

```bash
make install
make test
make lint
make golden-demo-dry-run
```

Python 3.11 or newer is required.

## Evidence contract

Every automated evaluator should answer four questions:

1. **What exact claim is being evaluated?**
2. **What evidence is collected?**
3. **What postcondition justifies the resulting status?**
4. **What limitation remains even when the evaluator succeeds?**

### Required rules

- Never map product or configuration presence directly to `PASS` when the control requires observed enforcement.
- Never convert a missing dependency, parser error or unavailable telemetry source into positive evidence.
- Every new automated evaluator needs tests and a documented evidence artifact.
- Prefer `PARTIAL`, `MANUAL` or `ERROR` when the full requirement cannot be proven.
- Preserve the distinction between declared, observed, linked and externally anchored evidence.
- Keep the authoritative Agent Baseline requirement prose upstream; this repository stores implementation mappings rather than silently forking the specification.
- Do not introduce a synthetic security/trust score unless its semantics and evidence model can be rigorously justified. The current project deliberately uses status transitions rather than a score.

## Safe probe rules

- No credential exfiltration.
- No destructive host probes.
- No unscoped organization-wide policy mutation.
- Use synthetic canaries and disposable resources.
- Prefer read-only observations and policy-decision checks.
- Dry-run paths must remain incapable of claiming live containment, revocation or runtime enforcement.

See [`SECURITY.md`](SECURITY.md) for the complete safety and disclosure policy.

## Tests

A change should include the narrowest regression test that proves its contract.

For evidence/verifier changes, include negative tests where practical. Examples:

- modified artifact must fail verification;
- wrong public key must fail signature verification;
- missing required invariant must not become an experiment match;
- coordinated local rewrite must not be mislabeled as externally anchored trust;
- future/unknown schema must fail closed.

Before proposing a change:

```bash
make test
make lint
```

If the change affects orchestration, packaging, response semantics or portable handoffs, also run:

```bash
make golden-demo-dry-run
```

## Documentation

Customer-facing behavior should be reflected in the relevant document:

- `docs/CUSTOMER_POC.md` — success criteria / PoC workflow;
- `docs/DEMO_GUIDE.md` — short walkthrough;
- `docs/ARCHITECTURE.md` — architecture and trust boundaries;
- `docs/CLAIMS_BOUNDARY.md` — explicit non-claims;
- `docs/ROADMAP.md` — implemented versus environment-dependent work.

## Pull-request quality bar

A strong contribution is:

- narrowly scoped;
- reproducible;
- safe to run in the documented environment;
- explicit about evidence and limitations;
- covered by tests;
- compatible with offline verification where applicable;
- free of real secrets, customer data and private signing material.
