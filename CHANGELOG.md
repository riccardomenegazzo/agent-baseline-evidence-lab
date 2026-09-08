# Changelog

All notable project changes are documented here.

## 0.7.0 — 2026-09-08

### Added

- portable Ed25519 evidence signing using OpenSSH SSH signatures;
- independent signature verification with externally pinnable signer fingerprints;
- optional Sigstore Rekor SSH-signature publication and inclusion verification adapter;
- signed/verified Agent Baseline source locks;
- Docker MCP runtime registration and secret-free OAuth status evidence;
- Docker AI Governance MCP evaluation/invocation/execution chain correlation;
- explicit `invokePrimordial` analysis and dynamic-gateway restrictions;
- direct-MCP bypass boundary test combining MCP and network policy evidence;
- explicit Docker-hosted MCP OAuth credential revocation with before/after verification;
- OBS-03 behavior drift profiles;
- OBS-04 credential/code co-change detector using path metadata only;
- append-only component quarantine registry;
- tested non-agent fallback workflow evidence;
- evidence-preserving incident bundles and independent incident-manifest verification;
- artifact schema registry and conservative response-drill migration;
- v0.7 assurance workflow documentation.

### Hardened

- Docker MCP reference policies now block dynamic gateway expansion through selected `invokePrimordial` resources;
- CI dependencies are pinned by commit SHA;
- CI now exercises the evidence attack matrix, incident preservation, real ephemeral Ed25519 signatures, fingerprint verification and non-publishing Rekor dry runs;
- dry-run contracts explicitly assert that no live containment, OAuth revocation, MCP runtime enforcement or transparency-log publication is claimed.

### Still intentionally unclaimed

- a real finalized Docker AI Governance MCP evaluation/execution pair;
- exact correlation of that governed pair to a specific live coding task;
- live OAuth revocation against a disposable authorization;
- a public Rekor entry;
- signer identity without an externally trusted key/fingerprint channel.

## 0.6.0 — 2026-09-07

- single-command manager-facing interview orchestration;
- tested sandbox containment and disposable sandbox-scoped credential-binding revocation;
- immutable assessment-to-response link statements and independent verification;
- Docker audit run-marker correlation with explicit evidence-strength grades;
- adversarial evidence verification matrix;
- external completeness-witness reconciliation;
- upstream implementation test-method note for independent evidence and omission detection.

## 0.5.0

- live coding-agent evidence capsule;
- Docker Sandbox / Codex execution path;
- Docker DHI MCP vertical slice;
- Docker AI Governance local audit ingestion and semantic event normalization;
- unsigned in-toto-style run attestations.
