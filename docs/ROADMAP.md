# Roadmap

## V1 — evidence engine vertical slice

- [x] 35-control catalogue for v1.0-draft
- [x] Honest PASS / FAIL / PARTIAL / MANUAL model
- [x] Run-scoped evidence bundles
- [x] SHA-256 evidence manifest and verifier
- [x] Docker Sandboxes preflight and live CON-03 probe
- [x] Non-invasive network policy checks
- [x] Minimal toxic-capability detector
- [x] Artifact validation hook
- [x] HTML + JSON reports
- [x] Upstream baseline drift check

## V1.1 — MCP evidence

- [ ] `sbx mcp` inventory adapter
- [ ] MCP gateway tool-call audit ingestion
- [ ] Cedar policy decision mapping
- [ ] approval-gate evidence for AUT-05
- [ ] direct-MCP bypass scenario mapped to network policy

## V1.2 — end-to-end agent trace

- [ ] stable trace envelope from prompt → model → MCP → target system
- [ ] drift baselines for OBS-03
- [ ] unintended-action detector for credential/code co-commit scenario
- [ ] target-system outcome evidence

## V1.3 — response

- [ ] tested sandbox stop circuit breaker
- [ ] sandbox-scoped credential revocation adapter
- [ ] component quarantine registry
- [ ] evidence-preserving incident bundle

## Upstream objective

Use real implementation friction to propose a narrowly evidenced issue or PR to the Agent Baseline project before the public-comment window closes. Do not manufacture feedback merely for visibility.
