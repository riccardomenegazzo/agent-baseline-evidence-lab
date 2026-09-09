# Roadmap

This roadmap separates **implemented mechanisms** from **live evidence actually collected**.

A checked item means the mechanism exists in the repository and is covered by tests/CI where practical. It does not imply that a particular Docker organization, external identity provider or customer environment has produced corresponding live evidence.

> **Do not add a feature merely to make the project look complete. Add a mechanism only when its evidence semantics can be stated precisely and tested.**

---

## v0.3 — Evidence-driven customer PoC ✅

- [x] 35-control Agent Baseline v1.0-draft catalogue
- [x] explicit `PASS / FAIL / PARTIAL / MANUAL / N/A / ERROR` semantics
- [x] run-scoped evidence bundles
- [x] per-file SHA-256 evidence manifests
- [x] hash-chained normalized trace
- [x] Docker Sandbox preflight and live probes
- [x] non-invasive network-policy checks
- [x] adversarial scenario runner
- [x] Docker MCP Cedar policy analysis
- [x] optional Docker AI Governance audit ingestion
- [x] standalone JSON/HTML reports

## v0.4 — Live coding-agent evidence ✅

- [x] metadata-minimized live-run capsule
- [x] disposable per-run workspace
- [x] Docker Sandbox / coding-agent command path
- [x] before/after workspace digests
- [x] prompt/output digests with raw capture opt-in only
- [x] assessment import of verified execution capsule
- [x] artifact validation against the agent-modified workspace
- [x] bounded Docker AI Governance audit ingestion

## v0.5 — Governed MCP evidence ✅ implementation complete

- [x] `sbx mcp` inventory adapter
- [x] run-scoped audit correlation marker
- [x] evaluation → approval/deny → execution chain analyzer
- [x] `invokePrimordial` permit/forbid analysis
- [x] DHI policy regression checks
- [x] direct-MCP bypass probe
- [x] OAuth authorization-state adapter without token persistence
- [x] recursive credential/token redaction
- [x] behavioral drift baseline
- [x] credential-sensitive path + code co-change detector

Live environment work still required:

- [ ] capture a reproducible real Docker AI Governance `tool_invocation` + `tool_execution` pair
- [ ] obtain trustworthy request-level correlation material where exposed
- [ ] validate installed Docker Sandboxes/MCP lifecycle behavior before encoding further assumptions

## v0.6 — Response and incident evidence ✅

- [x] sandbox stop circuit breaker with postcondition verification
- [x] disposable sandbox-scoped credential revocation
- [x] Docker MCP OAuth local-removal adapter
- [x] explicit provider-revocation trust boundary
- [x] immutable assessment → response digest link
- [x] independent response-link verification
- [x] append-only quarantine registry
- [x] evidence-preserving incident bundle
- [x] non-agent fallback workflow
- [x] negative dry-run response regression tests

## v0.7 — Independent assurance and trust hardening ✅

- [x] adversarial evidence-verification matrix
- [x] single-file alteration detection
- [x] trace-truncation detection
- [x] coordinated-rewrite demonstration
- [x] external digest anchor
- [x] explicit completeness limitation
- [x] external completeness witness reconciliation
- [x] Ed25519 signing
- [x] externally supplied public-key verification
- [x] negative signature tests
- [x] consolidated post-run assurance suite
- [x] baseline-source lock and drift verification
- [x] evidence schema versioning and fail-closed migrations
- [x] unknown/future schema rejection

## v0.8 — Customer handoff and release readiness ✅

- [x] readiness profiles
- [x] verified baseline lock required by live readiness
- [x] distributable wheel/sdist build
- [x] installed-wheel smoke testing
- [x] deterministic portable customer evidence ZIP
- [x] per-file SHA-256/size manifest
- [x] nested evidence/signature verification
- [x] public verification-key handoff
- [x] private-key exclusion
- [x] ZIP traversal/symlink/duplicate/unmanifested-member protections
- [x] negative pack tampering tests

## v0.9 — Verified before/after governance handoff ✅

- [x] Governance Delta over independently verified evidence bundles
- [x] control transition classification
- [x] evidence gain/loss versus status improvement/regression
- [x] evaluator recovery/error and scope-change semantics
- [x] recomputable JSON + human-readable HTML
- [x] signed delta statement
- [x] deterministic comparison pack
- [x] offline comparison-pack verifier
- [x] automated GitHub Release pipeline

## v0.10 — Controlled Experiment Protocol ✅

- [x] separate observed delta from causal eligibility
- [x] `ELIGIBLE / NOT_ELIGIBLE / INSUFFICIENT_EVIDENCE`
- [x] baseline/agent/task/workspace/runtime invariants
- [x] governance-treatment fingerprint
- [x] unchanged treatment rejected as an experiment
- [x] missing invariant fails closed
- [x] recomputable JSON/HTML and tamper tests
- [x] signed experiment statement

`ELIGIBLE` means only that the measured invariants match and the declared treatment differs. It is not proof of causality.

## v0.11 — Customer Trust Flow + artifact trust ✅

### End-to-end orchestration

- [x] one Customer Trust Flow from agent execution to signed handoff
- [x] installable `abl-trust` entrypoint
- [x] explicit `off / observe / gate` Docker Scout modes
- [x] fail-closed dry-run flow
- [x] dedicated `customer-trust` CI workflow

### Trusted artifact plane

- [x] Docker Buildx OCI output
- [x] SBOM + provenance attestation generation
- [x] OCI descriptor digest/size verification
- [x] runnable image/config/layer relationship verification
- [x] attestation-manifest traversal
- [x] SPDX SBOM subject-binding verification
- [x] SLSA provenance subject-binding verification
- [x] portable trusted-artifact statement
- [x] host-path minimization before export
- [x] Docker Scout evidence collection and optional hard gate

### Agent → artifact lineage

- [x] agent session → post-agent workspace digest
- [x] workspace state → trusted OCI artifact digest
- [x] workspace mutation invalidation
- [x] artifact mutation invalidation
- [x] lineage verification and Ed25519 signing

### Customer decision and handoff

- [x] evidence-derived Customer Decision Brief
- [x] `BLOCKED / CONDITIONAL / EVIDENCE_READY / DRY_RUN`
- [x] SARIF 2.1.0 export
- [x] deterministic signed Customer Trust Handoff
- [x] nested customer evidence pack verification
- [x] portable trusted-artifact/signature
- [x] lineage/signature when available
- [x] decision JSON/HTML/signature
- [x] private-key and OCI binary exclusion
- [x] local-path leakage rejection
- [x] duplicate/unmanifested ZIP rejection

### Release supply-chain dogfooding

- [x] GitHub Artifact Attestation generation
- [x] SLSA provenance for wheel/sdist/checksums/manifest
- [x] publication blocked unless `gh attestation verify` succeeds

## v0.12 — Versioned customer policy profiles ✅

- [x] installable `abl-policy` CLI
- [x] canonical versioned YAML policy profiles
- [x] customer decision evaluation without evidence rewriting
- [x] canonical policy SHA-256 binding
- [x] offline recomputation/verification
- [x] built-in `poc-observe` profile
- [x] built-in `enterprise-strict` profile
- [x] fail-closed unknown requirement handling

## v0.13 — Customer Acceptance Envelope ✅

- [x] installable `abl-accept` CLI
- [x] generic Customer Trust Handoff remains policy-neutral
- [x] customer-specific acceptance generated as a separate artifact
- [x] nested handoff verification before policy evaluation
- [x] signed policy evaluation
- [x] signed acceptance statement
- [x] signed final envelope
- [x] offline recomputation of policy result
- [x] policy/evaluation/statement/envelope tamper detection
- [x] built-in profiles shipped as wheel package data
- [x] clean-wheel release smoke tests for `abl-policy` and `abl-accept`

## v0.14 — Artifact-aware customer acceptance ✅

- [x] policy schema v2
- [x] direct `trusted-artifact.json` policy evaluation
- [x] trusted-artifact SHA-256 binding in policy evaluation
- [x] required trusted-artifact check status rules
- [x] required OCI evidence facts (`sbom_present`, `provenance_present`, `subject_bindings_valid`)
- [x] duplicate trusted-artifact check IDs fail closed
- [x] missing required artifact evidence fails closed
- [x] built-in `enterprise-supply-chain` profile
- [x] artifact-aware Customer Acceptance Envelope
- [x] acceptance statement binds nested trusted-artifact digest
- [x] verifier extracts trusted artifact from the signed handoff rather than accepting an unrelated file
- [x] artifact mutation invalidates policy verification
- [x] schema-v1 policy evaluations remain verifiable
- [x] v1/v2 acceptance envelope verification compatibility
- [x] release wheel smoke tests include the artifact-aware built-in profile

---

# Next high-value work

The next milestones are deliberately **not** additional scoring or superficial policy knobs.

## Real Docker AI Governance reference evidence

- [ ] retain a reproducible non-sensitive live MCP run
- [ ] capture governed evaluation/execution evidence with available stable IDs
- [ ] publish a sanitized reference fixture only when privacy and claims boundaries are defensible
- [ ] produce a manager-demo-quality live Customer Trust Flow from a dedicated lab environment

## Stronger external signer identity

- [ ] organization/keyless identity binding for customer handoff signatures
- [ ] documented customer key rotation and trust distribution
- [ ] optional transparency-log publication where interoperable
- [ ] multiple approved verification identities in a trust policy

## Provider-side response postconditions

- [ ] provider-specific server-side revocation adapters only where a verifiable postcondition exists
- [ ] distinguish provider API acknowledgement from independently observed invalidation

## Artifact policy depth

- [ ] deterministic before/after OCI artifact diff evidence
- [ ] optional base-image material identity requirements derived from provenance
- [ ] reference DHI comparison where entitlement and reproducibility permit it
- [ ] vulnerability-policy facts only when semantics can be derived from stable Scout result data rather than text scraping

## Customer enablement

- [x] executive overview
- [x] Customer PoC
- [x] manager/customer demo guide
- [x] downloadable releases
- [x] Customer Trust Flow
- [x] Customer Decision Brief
- [x] SARIF export
- [x] reusable customer policy profiles
- [x] Customer Acceptance Envelope
- [ ] sanitized non-sensitive live evidence fixture
- [ ] reusable workshop/facilitator kit

---

# Upstream objective

Use reproducible implementation friction to propose narrowly evidenced Agent Baseline test methods or control feedback. Do not manufacture upstream feedback merely for visibility.

High-value upstream-quality material now includes:

- independent evidence-verification matrix;
- integrity vs external anchoring vs completeness distinction;
- portable handoff trust boundary;
- Governance Delta transition model;
- Controlled Experiment eligibility boundary;
- OCI attestation subject-binding checks;
- agent → workspace → artifact lineage model;
- observation-versus-gating semantics;
- policy-neutral evidence versus customer-specific acceptance;
- artifact-aware policy evaluation with immutable evidence binding.

The strongest next upstream milestone remains a reproducible **real Docker AI Governance run** with governed MCP evaluation/execution evidence and explicit privacy/claims boundaries.
