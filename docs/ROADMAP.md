# Roadmap

This roadmap separates **implemented capability** from **live evidence already collected**. A checked item means the mechanism exists in the repository and is covered by tests/CI where practical; it does not imply that a particular Docker AI Governance organization or external provider has produced corresponding live evidence.

The roadmap follows one rule:

> **Do not add a feature merely to make the project look complete. Add a mechanism only when its evidence semantics can be stated precisely and tested.**

---

## v0.3 — evidence-driven customer PoC ✅

- [x] 35-control catalogue for Agent Baseline v1.0-draft
- [x] honest `PASS / FAIL / PARTIAL / MANUAL / N/A / ERROR` model
- [x] run-scoped evidence bundles
- [x] per-file SHA-256 evidence manifest
- [x] append-only SHA-256 hash-chained trace ledger
- [x] external manifest / trace-head verification anchors
- [x] Docker Sandboxes preflight and live CON-03 probes
- [x] non-invasive network policy checks
- [x] executable adversarial scenario runner
- [x] Docker MCP Cedar static-analysis adapter
- [x] optional Docker AI Governance local audit JSONL ingestion
- [x] artifact validation hooks
- [x] standalone HTML + JSON reports
- [x] upstream baseline drift check
- [x] customer PoC and success-criteria guide

## v0.4 — live coding-agent evidence ✅

- [x] metadata-only `abl live-run` capsule
- [x] disposable per-run workspace
- [x] real Docker Sandbox / Codex command path
- [x] before/after workspace root digest and changed-path evidence
- [x] prompt/output digests with raw capture opt-in only
- [x] assessment import of verified execution capsule
- [x] artifact checks resolved against agent-modified workspace
- [x] time-windowed Docker AI Governance audit ingestion
- [x] Docker DHI MCP live-demo configuration
- [x] CI dry-run coverage for live-run ingestion

## v0.5 — governed MCP execution evidence

### Implemented and testable

- [x] `sbx mcp` registration inventory adapter with identity/URL matching
- [x] documented-table fallback for `sbx mcp ls`
- [x] run-scoped Docker audit correlation marker
- [x] bounded evaluation → approval/deny → execution chain analyzer
- [x] explicit `invokePrimordial` permit-vs-forbid analysis
- [x] DHI policy regression checks for restricted capabilities
- [x] direct-MCP bypass policy probe
- [x] metadata-only OAuth authorization-state adapter
- [x] recursive secret/token redaction
- [x] behavioral drift baseline
- [x] credential-sensitive path + code co-change detector

### Live evidence still environment-dependent

- [ ] collect a real Docker AI Governance `tool_invocation` + `tool_execution` pair from a governed organization
- [ ] obtain an `exact-marker` correlation result from finalized Docker audit JSONL
- [ ] exercise a real evaluation → approval/deny → execution sequence preserving available source event IDs
- [ ] live-test direct-MCP bypass prevention against installed `sbx` network-policy lifecycle
- [ ] confirm installed Docker Sandboxes lifecycle for static MCP preloading before changing provisioning semantics

The action-chain analyzer intentionally reports **bounded correlation**, not strict causality, when the event model lacks a request-level causal identifier.

## v0.6 — response and incident evidence ✅

- [x] sandbox stop circuit breaker with postcondition verification
- [x] disposable sandbox-scoped credential-binding revocation
- [x] Docker MCP OAuth removal adapter with fail-closed dry-run default
- [x] provider-revocation boundary: local removal != server-side invalidation
- [x] immutable assessment → response digest link
- [x] independent response-link verifier
- [x] append-only quarantine registry
- [x] evidence-preserving incident bundle with per-artifact SHA-256
- [x] automatic quarantine + incident bundle in live flow
- [x] tested non-agent fallback workflow
- [x] dry-run regression tests forbidding positive response claims

## v0.7 — independent assurance and trust hardening ✅

### Integrity and independent verification

- [x] adversarial evidence-verification matrix
- [x] single-file alteration detection
- [x] trace-truncation detection
- [x] coordinated-rewrite test demonstrating local-anchor limitations
- [x] external digest anchor detecting coordinated rewrite
- [x] explicit `event-never-emitted` completeness limitation
- [x] external completeness-witness reconciliation
- [x] Ed25519 signing backend for exact evidence artifacts
- [x] externally supplied public-key verification
- [x] negative signature tests for subject mutation and wrong key
- [x] consolidated post-run assurance suite
- [x] separation of signature validity from external signer identity

### Baseline and schema trust

- [x] baseline-source lock with source digest, control IDs, version/status and drift
- [x] independent baseline-lock verifier
- [x] Ed25519-signable baseline lock workflow
- [x] evidence schema versioning
- [x] fail-closed migrations
- [x] future/unknown schema rejection
- [x] `.abl/` excluded from Git

## v0.8 — customer handoff and release readiness ✅

- [x] `community` and `mcp` readiness profiles
- [x] verified baseline lock required by live readiness
- [x] canonical baseline-cache path
- [x] live demos gated before sandbox creation
- [x] distributable wheel/sdist build in CI
- [x] wheel reinstall/smoke testing
- [x] deterministic portable customer evidence ZIP
- [x] per-file SHA-256/size manifest
- [x] embedded assessment-bundle verification after extraction
- [x] embedded Ed25519 signature verification when present
- [x] public verification-key handoff
- [x] private-key exclusion
- [x] no raw `agent-runs/` capsule in default handoff
- [x] incident artifact root/digest validation
- [x] ZIP traversal/symlink/duplicate/unmanifested-member protections
- [x] negative pack tamper tests
- [x] CI customer-pack verification and privacy assertions

## v0.9 — verified before/after governance handoff ✅

- [x] Governance Delta over independently verified evidence bundles
- [x] control-by-control transition classification
- [x] control improvement/regression versus evidence gain/loss
- [x] evaluator recovery/error and scope-change semantics
- [x] no synthetic security/trust score
- [x] recomputable delta JSON + human-readable HTML
- [x] Ed25519-signable delta statement
- [x] deterministic comparison pack
- [x] common public verification key embedded
- [x] private signing-key exclusion
- [x] distinct-run requirement
- [x] offline comparison-pack verifier
- [x] automated GitHub Release pipeline with wheel, sdist, checksums and source-bound manifest

## v0.10 — Controlled Experiment Protocol ✅

- [x] separate observed-status delta from causal-eligibility analysis
- [x] `ELIGIBLE`, `NOT_ELIGIBLE`, `INSUFFICIENT_EVIDENCE`
- [x] baseline-version invariant
- [x] agent-identity invariant
- [x] task identity/SHA-256 invariants
- [x] initial-workspace SHA-256 invariant
- [x] agent runtime invariant
- [x] Docker Sandbox runtime fingerprint invariant
- [x] deterministic governance-treatment fingerprint
- [x] missing required invariant fails closed
- [x] unchanged treatment is not mislabeled as an experiment
- [x] recomputable JSON + human-readable HTML
- [x] tamper-detection tests
- [x] Ed25519 signing workflow
- [x] customer-facing experiment documentation

`ELIGIBLE` means only that the **measured** invariants match and the declared governance treatment differs. It does not prove causality.

## v0.11 — Customer Trust Flow + artifact trust ✅ implementation complete

### End-to-end customer trust orchestration

- [x] one Customer Trust Flow from agent execution to signed customer handoff
- [x] installable `abl-trust` entrypoint
- [x] explicit `off / observe / gate` Docker Scout modes
- [x] fail-closed dry-run flow
- [x] dedicated `customer-trust` CI workflow
- [x] dry-run contract forbidding positive live lineage/enforcement claims

### Trusted artifact plane

- [x] Docker Buildx OCI output path
- [x] SBOM attestation generation
- [x] provenance attestation generation
- [x] OCI descriptor digest/size verification
- [x] runnable image/config relationship verification
- [x] attestation-manifest traversal
- [x] SBOM subject-binding verification
- [x] provenance subject-binding verification
- [x] portable trusted-artifact statement
- [x] host-path minimization before customer export
- [x] Docker Scout evidence collection
- [x] Docker Scout hard-gate semantics when explicitly configured

### Agent → artifact lineage

- [x] lineage binds agent session to post-agent workspace digest
- [x] lineage binds workspace state to trusted OCI artifact digest
- [x] workspace mutation after agent run fails lineage creation
- [x] artifact mutation after trusted-artifact generation fails lineage creation
- [x] lineage statement verification
- [x] lineage Ed25519 signature

### Decision and integrations

- [x] evidence-derived Customer Decision Brief
- [x] `BLOCKED / CONDITIONAL / EVIDENCE_READY / DRY_RUN` disposition model
- [x] no synthetic trust score
- [x] human-readable decision HTML
- [x] SARIF 2.1.0 export for security-tool integration

### Customer Trust Handoff

- [x] deterministic manifest-driven trust handoff ZIP
- [x] nested customer evidence pack
- [x] nested customer pack signature verification
- [x] portable trusted-artifact + signature
- [x] agent-artifact lineage + signature when live lineage exists
- [x] decision JSON/HTML + signature
- [x] SARIF + sanitized supply-chain evidence
- [x] final handoff Ed25519 signature
- [x] private-key exclusion
- [x] OCI binary archive exclusion from default customer handoff
- [x] local project/home path leakage rejection
- [x] duplicate/unmanifested ZIP member rejection
- [x] negative tampering tests

### Release supply-chain dogfooding

- [x] GitHub Artifact Attestation generation in release workflow
- [x] SLSA provenance for wheel, sdist, `SHA256SUMS` and `release-manifest.json`
- [x] release publication blocked unless `gh attestation verify` succeeds
- [x] dedicated release provenance documentation

The v0.11 implementation is considered complete only when the versioned release is published from an all-green final commit and the newly published release attestations verify.

---

# Next: stronger live enterprise evidence and identity

Future work remains deliberately narrow.

## Live Docker governance evidence

- [ ] retain a reproducible real Docker AI Governance MCP run without prompt/credential/customer leakage
- [ ] obtain trustworthy request-level correlation material where the product exposes it
- [ ] validate installed Docker Sandboxes/MCP behavior before encoding new assumptions
- [ ] capture a manager-demo-quality live Customer Trust Flow from a non-sensitive lab environment

## Stronger external identity

- [ ] organization/keyless identity binding for customer handoff signatures
- [ ] documented customer key-rotation/trust-distribution model
- [ ] optional transparency-log publication where interoperable and useful
- [ ] explicit trust-policy support for multiple approved verification identities

## Provider postconditions

- [ ] provider-specific server-side revocation adapters only when a verifiable postcondition exists
- [ ] explicit distinction between provider API acknowledgement and independently observed invalidation

## Artifact policy depth

- [ ] reusable customer policy profiles for common Scout/base-image/SBOM/provenance requirements
- [ ] policy-profile version binding in customer decision evidence
- [ ] optional reference DHI comparison where entitlement and reproducibility allow it
- [ ] deterministic artifact-diff evidence for before/after base-image treatments

## Customer enablement

- [x] executive overview
- [x] measurable Customer PoC
- [x] concise manager/customer demo guide
- [x] downloadable releases
- [x] Customer Trust Flow HTML
- [x] Customer Decision Brief
- [x] security-tool SARIF export
- [ ] sanitized reference live evidence fixture generated from an explicitly non-sensitive environment
- [ ] reusable workshop/facilitator kit derived from the live Customer Trust Flow

A sanitized live fixture will be added only when it can be generated without misleading claims or environment-specific sensitive identifiers.

---

# Upstream objective

Use reproducible implementation friction to propose narrowly evidenced Agent Baseline test methods or control feedback. Do not manufacture feedback merely for visibility.

High-value upstream-quality material now includes:

- independent-evidence verification matrix;
- coordinated-rewrite result;
- completeness-witness model;
- integrity vs external anchoring vs completeness distinction;
- portable handoff trust boundary;
- Governance Delta transition model;
- Controlled Experiment eligibility boundary;
- OCI attestation subject-binding checks;
- agent → workspace → artifact lineage model;
- explicit observation-versus-gating policy semantics.

The strongest next upstream milestone remains a reproducible **real Docker AI Governance run** containing governed MCP evaluation/execution evidence with explicit privacy and claims boundaries.
