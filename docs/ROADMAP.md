# Roadmap

This roadmap separates **implemented capability** from **live evidence already collected**. A checked item means the mechanism exists in the repository and is covered by tests/CI where practical; it does not imply that a particular Docker AI Governance organization or external provider has produced the corresponding live event.

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
- [x] run-scoped pseudonymization for user/org/host audit fields
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
- [x] assessment import of the execution capsule
- [x] artifact checks resolved against the agent-modified workspace
- [x] time-windowed Docker AI Governance audit ingestion
- [x] Docker DHI MCP live-demo configuration
- [x] read-only DHI-specific MCP Cedar reference policy
- [x] CI dry-run coverage for the live-run ingestion path

## v0.5 — governed MCP execution evidence

### Implemented and testable

- [x] `sbx mcp` registration inventory adapter with identity/URL matching
- [x] documented-table fallback for `sbx mcp ls`
- [x] run-scoped Docker audit correlation marker
- [x] bounded evaluation → approval/deny → execution chain analyzer
- [x] explicit `invokePrimordial` permit-vs-forbid analysis
- [x] regression test that the DHI policy forbids `mcp-add` and `code-mode`
- [x] direct-MCP bypass policy probe, separate from host-side gateway traffic
- [x] metadata-only OAuth authorization-state adapter
- [x] recursive redaction of token/secret/password/cookie/authorization fields
- [x] behavioral drift baseline for event types, destinations and MCP targets
- [x] credential-sensitive path + code co-change detector

### Live evidence still environment-dependent

- [ ] collect a real Docker AI Governance `tool_invocation` + `tool_execution` pair from a governed organization
- [ ] obtain an `exact-marker` correlation result from finalized Docker audit JSONL
- [ ] exercise a real evaluation → approval/deny → execution sequence and preserve available source event IDs
- [ ] live-test direct-MCP bypass prevention against the installed `sbx` network-policy lifecycle
- [ ] confirm installed Docker Sandboxes lifecycle for static MCP preloading before changing provisioning semantics

The action-chain analyzer intentionally reports **bounded correlation**, not strict causality, when the available event model does not expose a request-level causal identifier.

## v0.6 — response and incident evidence ✅

- [x] tested sandbox stop circuit breaker with postcondition verification
- [x] disposable sandbox-scoped credential-binding revocation
- [x] explicit Docker MCP OAuth removal adapter with fail-closed dry-run default
- [x] provider-revocation boundary: local credential removal != server-side token invalidation
- [x] immutable assessment → response digest link
- [x] independent response-link verifier
- [x] append-only quarantine registry
- [x] evidence-preserving incident bundle with per-artifact SHA-256
- [x] automatic quarantine + incident-bundle creation in the live customer flow
- [x] tested non-agent fallback workflow
- [x] dry-run regression tests forbidding positive containment/revocation/quarantine/incident claims

## v0.7 — independent assurance and trust hardening ✅

### Integrity and independent verification

- [x] adversarial evidence-verification matrix
- [x] single-file alteration detection
- [x] trace-truncation detection
- [x] coordinated-rewrite test proving the limitation of self-consistent local anchors
- [x] external digest anchor detecting coordinated rewrite
- [x] explicit `event-never-emitted` completeness limitation
- [x] external completeness-witness reconciliation
- [x] Ed25519 signing backend for exact evidence artifacts
- [x] externally supplied public-key verification
- [x] negative signature tests for subject mutation and wrong key
- [x] consolidated post-run assurance suite with blocking failures vs non-blocking findings
- [x] explicit separation of signature validity from external signer identity

### Baseline and schema trust

- [x] baseline-source lock containing source digest, control IDs, version/status and drift
- [x] independent baseline-lock verifier before signing
- [x] Ed25519-signable baseline lock workflow
- [x] evidence schema versioning
- [x] fail-closed migrations that never invent positive claims
- [x] future/unknown schema rejection
- [x] `.abl/` excluded from Git to protect local signing keys and response state

## v0.8 — customer handoff and release readiness ✅

- [x] machine-readable `community` pre-demo readiness profile
- [x] machine-readable `mcp` readiness profile with DHI endpoint identity check
- [x] verified baseline lock required by live readiness
- [x] one canonical baseline-cache path across sync/verify/sign/readiness
- [x] live customer demos gated before sandbox creation; CI dry-run remains Docker-independent
- [x] distributable wheel/sdist build in CI
- [x] reinstall and smoke-test built wheels rather than relying only on editable installs
- [x] deterministic portable customer evidence ZIP for one assessment run
- [x] portable-pack manifest with per-file SHA-256 and size
- [x] embedded assessment-bundle verification after offline extraction
- [x] embedded Ed25519 signature verification when signature evidence is present
- [x] public verification-key handoff with explicit private-key exclusion
- [x] no raw `agent-runs/` capsule in the default customer handoff
- [x] incident-referenced artifacts copied only when inside the project root and digest-valid
- [x] ZIP path-traversal, symlink, duplicate-member and unmanifested-member protections
- [x] negative tests for pack tampering and out-of-root incident evidence
- [x] CI customer-pack creation, verification and private-key exclusion assertion

The portable pack is a transport artifact, not an external trust anchor. Its final ZIP SHA-256 should be pinned or signed through an independent channel when handoff authenticity matters.

## v0.9 — verified before/after governance handoff ✅

- [x] Governance Delta over two independently verified evidence bundles
- [x] control-by-control transition classification
- [x] explicit control improvement/regression versus evidence gain/loss
- [x] evaluator recovery/error and scope-change semantics
- [x] no synthetic security/trust score
- [x] independently recomputable delta JSON
- [x] human-readable delta HTML
- [x] Ed25519-signable delta statement
- [x] deterministic comparison pack containing before/after customer evidence
- [x] common public verification key embedded in the handoff
- [x] private signing key exclusion
- [x] distinct-run requirement for the comparison handoff
- [x] offline comparison-pack verifier
- [x] automated GitHub Release pipeline with wheel, sdist, `SHA256SUMS` and source-bound release manifest

## v0.10 — Controlled Experiment Protocol ✅

- [x] separate observed-status delta from causal-eligibility analysis
- [x] explicit `ELIGIBLE`, `NOT_ELIGIBLE`, `INSUFFICIENT_EVIDENCE` outcomes
- [x] baseline-version invariant
- [x] agent-identity invariant
- [x] task identity and SHA-256 invariants
- [x] initial-workspace SHA-256 invariant
- [x] agent runtime invariant
- [x] Docker Sandbox runtime fingerprint invariant
- [x] deterministic governance-treatment fingerprint
- [x] missing required invariant fails closed to `INSUFFICIENT_EVIDENCE`
- [x] unchanged treatment is not mislabeled as an experiment
- [x] recomputable JSON experiment statement
- [x] human-readable experiment HTML
- [x] tamper-detection tests
- [x] Ed25519 signing workflow
- [x] customer-facing experiment protocol documentation

`ELIGIBLE` intentionally means only that the **measured** invariants match and the declared governance treatment differs. It does not prove causality or exclude unmeasured confounders.

---

## Next: stronger external trust and live enterprise evidence

Future work is deliberately narrow.

### External identity / publication

- [ ] optional public transparency-log publication using a representation verified to be interoperable with the selected log client
- [ ] external or keyless identity binding for signing material instead of local key possession alone
- [ ] documented key-rotation / trust-distribution model for customer handoffs

### Provider postconditions

- [ ] provider-specific server-side revocation adapters only where a provider exposes a verifiable revocation postcondition
- [ ] explicit distinction between provider API acknowledgement and independently observed invalidation

### Live Docker governance evidence

- [ ] retain a reproducible real Docker AI Governance MCP run without leaking prompt content, credentials or customer-sensitive metadata
- [ ] strengthen run-to-audit correlation only when the source event model provides trustworthy correlation material
- [ ] validate current Docker Sandboxes/MCP integration behavior against the installed product version before encoding new assumptions

### Customer enablement

- [x] executive overview
- [x] measurable Customer PoC
- [x] concise customer demo guide
- [x] downloadable verified releases
- [ ] optional sanitized reference evidence fixture generated from a real, explicitly non-sensitive lab run

A sanitized reference fixture will be added only when it can be generated without creating misleading "live" claims or embedding environment-specific identifiers.

---

## Upstream objective

Use reproducible implementation friction to propose narrowly evidenced Agent Baseline test methods or control feedback. Do not manufacture feedback merely for visibility.

High-value upstream-quality material currently includes:

- the independent-evidence verification matrix;
- the coordinated-rewrite result;
- the completeness-witness model;
- the distinction between integrity, external anchoring and source completeness;
- the portable handoff model separating shareable evidence from private/local execution state;
- the Governance Delta transition model;
- the Controlled Experiment eligibility boundary.

The strongest next upstream milestone remains a reproducible **real Docker AI Governance run** containing governed MCP evaluation/execution evidence with explicit privacy and claims boundaries.
