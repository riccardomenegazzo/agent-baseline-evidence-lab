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

- [ ] capture a real Docker AI Governance `tool_invocation` + `tool_execution` pair
- [ ] derive or propagate a stronger cross-system correlation key between agent task and Docker audit session
- [ ] `sbx mcp` registration inventory adapter with identity/URL matching
- [ ] correlate evaluation → approval/deny → tool execution outcome
- [ ] test explicit `invokePrimordial` restrictions for dynamic gateway tools
- [ ] direct-MCP bypass scenario mapped jointly to MCP + network policy
- [ ] evidence model for OAuth authorization state without collecting secrets
- [ ] OBS-03 drift baseline for destinations/tool use/resource consumption
- [ ] OBS-04 unintended-action detector for credential/code co-commit scenarios

## V0.6 — response exercise

- [ ] tested sandbox stop circuit breaker
- [ ] credential/permit revocation evidence adapter where available
- [ ] component quarantine registry
- [ ] evidence-preserving incident bundle
- [ ] tested non-agent fallback workflow

## Trust hardening

- [ ] portable digital signature for the final evidence anchor
- [ ] optional transparency-log publication
- [ ] signed baseline-source lock
- [ ] evidence schema versioning and migration tests

## Upstream objective

Use reproducible implementation friction to propose a narrowly evidenced issue or PR to the Agent Baseline project. Do not manufacture feedback merely for visibility.

The immediate upstream-quality milestone is a reproducible real governance run containing an MCP evaluation/execution pair **without leaking prompt content, credentials, or customer-sensitive metadata**.
