# Roadmap

This roadmap separates **implemented capability** from **live evidence already collected**. A checked item means the mechanism exists in the repository and is covered by tests/CI where practical; it does not imply that a Docker AI Governance organization has produced the corresponding live event yet.

## V0.3 — evidence-driven customer PoC ✅

- [x] 35-control catalogue for Agent Baseline v1.0-draft
- [x] honest PASS / FAIL / PARTIAL / MANUAL / N/A / ERROR model
- [x] run-scoped evidence bundles
- [x] per-file SHA-256 evidence manifest
- [x] append-only SHA-256 hash-chained trace ledger
- [x] external manifest/trace-head verification anchors
- [x] Docker Sandboxes preflight and live CON-03 probes
- [x] non-invasive network policy checks
- [x] executable VAL-01 adversarial scenario runner
- [x] Docker MCP Cedar static-analysis adapter
- [x] Docker AI Governance local audit JSONL ingestion
- [x] run-scoped pseudonymization for user/org/host audit fields
- [x] artifact validation hooks
- [x] standalone HTML + JSON reports
- [x] upstream baseline drift check
- [x] customer PoC and success-criteria guide

## V0.4 — live coding-agent evidence ✅

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

## V0.5 — governed MCP execution evidence

### Implemented and testable

- [x] `sbx mcp` registration inventory adapter with identity/URL matching
- [x] documented-table fallback for `sbx mcp ls`
- [x] run-scoped Docker audit correlation marker
- [x] bounded evaluation → approval/deny → execution chain analyzer
- [x] explicit `invokePrimordial` permit-vs-forbid analysis
- [x] regression test that DHI policy forbids `mcp-add` and `code-mode`
- [x] direct-MCP bypass policy probe, separate from host-side gateway traffic
- [x] metadata-only OAuth authorization-state adapter
- [x] recursive redaction of token/secret/password/cookie/authorization fields
- [x] OBS-03 behavioral drift baseline for event types, destinations and MCP targets
- [x] OBS-04 credential-sensitive path + code co-change detector

### Live evidence still required

- [ ] collect a real Docker AI Governance `tool_invocation` + `tool_execution` pair from a governed organization
- [ ] obtain an `exact-marker` correlation result from finalized Docker audit JSONL
- [ ] exercise a real evaluation → approval/deny → execution sequence and preserve all source event IDs
- [ ] live-test direct-MCP bypass prevention against the actual installed `sbx` network policy lifecycle
- [ ] confirm the installed Docker Sandboxes CLI lifecycle for static MCP preloading before changing provisioning semantics

The action-chain analyzer intentionally reports **bounded correlation**, not strict causality, because Docker currently documents unique event IDs and daemon-session IDs but no request-level causal identifier.

## V0.6 — response and incident evidence ✅

- [x] tested sandbox stop circuit breaker with postcondition verification
- [x] disposable sandbox-scoped credential-binding revocation
- [x] explicit Docker MCP OAuth removal adapter with fail-closed dry-run default
- [x] provider-revocation claims boundary: local credential removal != server-side token invalidation
- [x] immutable assessment → response digest link
- [x] independent response-link verifier
- [x] append-only quarantine registry
- [x] evidence-preserving incident bundle with per-artifact SHA-256
- [x] automatic quarantine + incident bundle creation in the live manager flow
- [x] tested non-agent fallback workflow
- [x] dry-run regression tests that forbid positive containment/revocation/quarantine/incident claims

## V0.7 — independent assurance and trust hardening ✅

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

## V0.8 — customer handoff and release readiness ✅

- [x] machine-readable `community` pre-demo readiness profile
- [x] machine-readable `mcp` readiness profile with DHI endpoint identity check
- [x] verified baseline lock required by readiness
- [x] one canonical baseline cache path across sync/verify/sign/readiness
- [x] live manager demos gated before sandbox creation; CI dry-run remains Docker-independent
- [x] distributable wheel/sdist build in CI
- [x] reinstall and smoke-test the built wheel rather than relying only on editable installs
- [x] deterministic portable customer evidence ZIP for one assessment run
- [x] portable-pack manifest with per-file SHA-256 and size
- [x] embedded assessment-bundle verification after offline extraction
- [x] embedded Ed25519 signature verification when signature evidence is present
- [x] public verification key handoff with explicit private-key exclusion
- [x] no raw `agent-runs/` capsule in the default customer handoff
- [x] incident-referenced artifacts copied only when inside the project root and digest-valid
- [x] ZIP path-traversal, symlink, duplicate-member and unmanifested-member protections
- [x] negative tests for pack tampering and out-of-root incident evidence
- [x] CI customer-pack creation, verification and private-key exclusion assertion

The portable pack is a transport artifact, not an external trust anchor. Its final ZIP SHA-256 should be pinned or signed through an independent channel when handoff authenticity matters.

## Still pending trust / enterprise integrations

- [ ] optional public transparency-log publication (for example Sigstore/Rekor) using a format verified to be interoperable with the chosen log client
- [ ] external/keyless identity binding for the signing key rather than local possession alone
- [ ] provider-specific server-side revocation adapters only where a provider exposes a verifiable revocation postcondition

The repository deliberately does **not** call the local Ed25519 key identity an external identity, and does not mark transparency logging complete until the signature representation is confirmed interoperable with a supported publication path.

## Upstream objective

Use reproducible implementation friction to propose narrowly evidenced Agent Baseline test methods or control feedback. Do not manufacture feedback merely for visibility.

Current upstream-quality material includes:

- the independent-evidence verification matrix;
- the coordinated-rewrite result;
- the completeness-witness model;
- the explicit distinction between integrity, external anchoring and source completeness;
- the portable handoff model separating shareable evidence from private/local execution state.

The strongest next upstream milestone remains a reproducible **real Docker AI Governance run** containing governed MCP evaluation/execution evidence without leaking prompt content, credentials, or customer-sensitive metadata.
