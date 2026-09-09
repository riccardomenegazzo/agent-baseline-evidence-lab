# Roadmap

This roadmap separates **implemented mechanisms** from **live evidence actually collected**.

A checked item means the mechanism exists in the repository and is covered by tests/CI where practical. It does not imply that a particular Docker organization, external identity provider or customer environment has produced corresponding live evidence.

> **Do not add a feature merely to make the project look complete. Add a mechanism only when its evidence semantics can be stated precisely and tested.**

---

## v0.3 — Evidence-driven customer PoC ✅

- [x] 35-control Agent Baseline v1.0-draft catalogue
- [x] explicit evidence-status semantics
- [x] run-scoped evidence bundles and SHA-256 manifests
- [x] hash-chained normalized trace
- [x] Docker Sandbox probes
- [x] MCP Cedar policy analysis
- [x] optional Docker AI Governance audit ingestion

## v0.4 — Live coding-agent evidence ✅

- [x] metadata-minimized live-run capsule
- [x] disposable per-run workspace
- [x] Docker Sandbox / coding-agent execution path
- [x] before/after workspace digests
- [x] prompt/output digests with raw capture opt-in
- [x] assessment import of verified execution evidence

## v0.5 — Governed MCP evidence ✅ implementation complete

- [x] MCP inventory and identity/URL matching
- [x] bounded audit correlation
- [x] evaluation → approval/deny → execution analysis
- [x] `invokePrimordial` policy analysis
- [x] direct-MCP bypass probe
- [x] OAuth authorization-state adapter without token persistence
- [x] behavioral drift and credential-sensitive co-change detection

Live environment work remains for reproducible real Docker AI Governance event fixtures.

## v0.6 — Response and incident evidence ✅

- [x] sandbox stop postcondition verification
- [x] disposable credential revocation evidence
- [x] explicit provider-revocation trust boundary
- [x] response digest links
- [x] quarantine registry
- [x] evidence-preserving incident bundles
- [x] non-agent fallback workflow

## v0.7 — Independent assurance and trust hardening ✅

- [x] adversarial evidence-verification matrix
- [x] alteration/truncation/coordinated-rewrite tests
- [x] external digest anchoring
- [x] explicit completeness limitations
- [x] Ed25519 signing and external public-key verification
- [x] consolidated assurance suite
- [x] baseline-source lock and fail-closed schema migrations

## v0.8 — Customer handoff and release readiness ✅

- [x] readiness profiles and baseline-lock gate
- [x] wheel/sdist build and installed-wheel smoke tests
- [x] deterministic portable customer evidence ZIP
- [x] nested evidence/signature verification
- [x] private-key exclusion and archive-path hardening

## v0.9 — Verified before/after governance handoff ✅

- [x] Governance Delta over verified evidence bundles
- [x] evidence gain/loss versus status transition semantics
- [x] deterministic comparison pack and offline verifier
- [x] automated GitHub Release pipeline

## v0.10 — Controlled Experiment Protocol ✅

- [x] causal-eligibility separated from observed delta
- [x] `ELIGIBLE / NOT_ELIGIBLE / INSUFFICIENT_EVIDENCE`
- [x] baseline/agent/task/workspace/runtime invariants
- [x] governance-treatment fingerprint
- [x] signed, recomputable experiment statement

`ELIGIBLE` is not proof of causality.

## v0.11 — Customer Trust Flow + artifact trust ✅

- [x] end-to-end `abl-trust` orchestration
- [x] `off / observe / gate` Docker Scout modes
- [x] Docker Buildx OCI output with SBOM/provenance
- [x] recursive OCI graph verification
- [x] attestation subject-binding verification
- [x] agent → workspace → OCI artifact lineage
- [x] evidence-derived Customer Decision Brief
- [x] SARIF export
- [x] signed Customer Trust Handoff
- [x] release SLSA provenance dogfooding

## v0.12 — Versioned customer policy profiles ✅

- [x] `abl-policy` CLI
- [x] canonical YAML policy profiles and policy SHA-256
- [x] offline recomputation
- [x] `poc-observe` and `enterprise-strict` built-ins

## v0.13 — Customer Acceptance Envelope ✅

- [x] `abl-accept` CLI
- [x] policy-neutral generic handoff
- [x] separate signed customer-specific acceptance artifact
- [x] signed policy evaluation and acceptance statement
- [x] offline verification and tamper detection
- [x] built-in policy profiles shipped in the wheel

## v0.14 — Artifact-aware customer acceptance ✅

- [x] policy schema v2
- [x] direct trusted-artifact policy evaluation
- [x] trusted-artifact SHA-256 binding
- [x] required OCI evidence facts and check statuses
- [x] built-in `enterprise-supply-chain` profile
- [x] artifact-aware Customer Acceptance Envelope v2
- [x] schema-v1 backward verification compatibility

## v0.15 — Deterministic verified OCI artifact diff ✅

- [x] installable `abl-artifact-diff` CLI
- [x] both trusted-artifact reports must be `VERIFIED`
- [x] both OCI archive SHA-256 values revalidated before comparison
- [x] both recursive OCI graphs re-verified
- [x] both SBOM/provenance subject bindings re-verified
- [x] archive byte identity separated from runnable OCI graph identity
- [x] canonical runnable graph fingerprint over platform/manifest/config/ordered layers
- [x] canonical supply-chain evidence fingerprint
- [x] SLSA v0.x `materials` normalization
- [x] SLSA provenance-v1 `buildDefinition.resolvedDependencies` normalization
- [x] explicit same-URI material digest transitions
- [x] raw attestation statement changes remain separately visible
- [x] Dockerfile base-image evidence kept separate from provenance materials
- [x] `IDENTICAL` classification
- [x] `REPACKAGED_EQUIVALENT` classification
- [x] `BUILD_EVIDENCE_CHANGED` classification
- [x] `ARTIFACT_CHANGED` classification
- [x] JSON + human-readable HTML output
- [x] independent recomputation/verifier
- [x] tamper and archive-digest mismatch tests
- [x] tar reorder/mtime regression proving byte changes do not become false runnable changes

`REPACKAGED_EQUIVALENT` is bounded to the fields modeled by the verifier. It is not a claim of universal behavioral equivalence.

---

# Next high-value work

## Real Docker AI Governance reference evidence

- [ ] retain a reproducible non-sensitive live MCP run
- [ ] capture governed evaluation/execution evidence with available stable identifiers
- [ ] publish a sanitized reference fixture only when privacy and claims boundaries are defensible
- [ ] produce a manager-demo-quality live Customer Trust Flow from a dedicated lab environment

## Stronger external signer identity

- [ ] organization/keyless identity binding for customer handoff signatures
- [ ] customer key rotation and trust distribution
- [ ] optional transparency-log publication where interoperable
- [ ] multiple approved verification identities in a trust policy

## Artifact transition handoff

- [ ] deterministic signed before/after artifact-transition pack
- [ ] include verified OCI diff beside Governance Delta without conflating their semantics
- [ ] bind remediation intent only when an explicit change request/ticket identity is available
- [ ] optional artifact-diff acceptance policy for promotion workflows

## Provider-side response postconditions

- [ ] provider-specific server-side revocation adapters only where a verifiable postcondition exists
- [ ] distinguish API acknowledgement from independently observed invalidation

## Customer enablement

- [x] executive overview
- [x] Customer Trust Flow
- [x] Customer Decision Brief
- [x] SARIF export
- [x] customer policy profiles
- [x] Customer Acceptance Envelope
- [x] verified OCI Artifact Diff
- [x] downloadable provenance-backed releases
- [ ] sanitized non-sensitive live evidence fixture
- [ ] reusable workshop/facilitator kit

---

# Upstream objective

Use reproducible implementation friction to propose narrowly evidenced Agent Baseline test methods or control feedback. Do not manufacture upstream feedback merely for visibility.

The strongest next upstream milestone remains a reproducible **real Docker AI Governance run** with governed MCP evaluation/execution evidence and explicit privacy/claims boundaries.
