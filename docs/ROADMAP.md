# Roadmap

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

- [ ] capture a real Docker AI Governance `tool_invocation` + `tool_execution` pair on a governed organization
- [x] run-scoped cross-system correlation marker with explicit exact/bounded/ambiguous evidence grades
- [x] `sbx mcp inspect` runtime registration adapter with canonical identity-URL matching
- [x] evaluation / approval-or-deny / invocation / execution action-chain correlation
- [x] explicit `invokePrimordial` restrictions for dynamic gateway expansion
- [x] direct-MCP bypass scenario mapped jointly to MCP + network policy
- [x] OAuth authorization-state evidence with status/scope allowlisting and no token persistence
- [x] explicit Docker-hosted MCP OAuth credential revocation adapter with before/after verification
- [x] OBS-03 behavior drift baseline for destinations, MCP tools, event counts and available resource metrics
- [x] OBS-04 metadata-only unintended-action detector for credential/code co-change patterns

The remaining V0.5 item requires a real Docker AI Governance organization and finalized audit records. The code intentionally does not manufacture runtime proof in CI or offline mode.

## V0.6 — response exercise ✅

- [x] tested sandbox stop circuit breaker with post-state verification
- [x] sandbox-scoped disposable credential-binding revocation evidence
- [x] optional Docker-hosted MCP OAuth credential revocation evidence
- [x] append-only component quarantine registry linked to source evidence digests
- [x] evidence-preserving incident bundle with byte-for-byte copy verification
- [x] tested non-agent fallback execution path with metadata-only output evidence
- [x] immutable assessment-to-response link statement and independent verifier

## V0.7 — trust and assurance hardening ✅ implementation-complete

- [x] portable Ed25519 detached signatures using OpenSSH `ssh-keygen -Y sign`
- [x] independent signature verification using an externally pinnable public-key fingerprint
- [x] optional Sigstore Rekor publication adapter for SSH-signed evidence
- [x] baseline source lock verification and optional signature
- [x] artifact schema registry and conservative migration tests
- [x] adversarial evidence-verification matrix
- [x] independent completeness-witness reconciliation
- [x] incident-bundle integrity manifest
- [x] CI-safe dry-run contracts that cannot produce positive live-security claims

## Remaining external-runtime milestones

These are deliberately not checked until real external evidence exists:

1. collect a finalized Docker AI Governance MCP evaluation + execution chain from a governed organization;
2. obtain an `exact-marker` correlation between that Docker audit stream and one specific coding-agent run;
3. run OAuth revocation against a deliberately disposable OAuth authorization rather than a personal/customer credential;
4. publish one intentionally public signed demo manifest to Rekor and retain its verified inclusion receipt;
5. pin a demo signer fingerprint outside the evidence producer boundary;
6. run the complete customer-style PoC on a clean Mac and archive the resulting signed incident/evidence package.

## Upstream objective

Use reproducible implementation friction to propose narrowly evidenced test methods or implementation feedback to the Agent Baseline project. Do not manufacture feedback merely for visibility.

The repository already contains a reproducible independent-evidence test method demonstrating that:

- uncoordinated alteration and trace truncation are detectable internally;
- a coordinated rewrite of all local anchors requires an external trust anchor to detect;
- an event never emitted into the evidence pipeline cannot be recovered from artifact integrity alone;
- completeness therefore needs an independent source-of-record, sequence/checkpoint expectation, or reconciliation witness.

The next upstream-quality milestone is a real governed Docker MCP audit chain that adds runtime evidence beyond the existing offline and structural findings.
