# Agent Baseline Evidence Lab

**An executable, evidence-driven implementation assessment for the Agent Baseline v1.0-draft, with first-class Docker Sandboxes probes.**

> Community project. Not an official Docker, Snyk, Keycard, or Agent Baseline project. It does **not** issue certifications or claim official conformance.

The Agent Baseline asks enterprises to identify agents, bound authority, control actions, prove outcomes, and stop agents when things go wrong. This repository explores a practical question: **what evidence can we actually collect for those requirements from a real coding-agent environment?**

Instead of painting 35 controls green, the lab distinguishes `PASS`, `FAIL`, `PARTIAL`, `MANUAL`, and `N/A`, preserves run-scoped evidence, and makes unsupported claims visible.

## What works in V1

- all 35 v1.0-draft control IDs are represented;
- declared agent/component/access inventory is validated;
- a minimal toxic-capability detector identifies a known dangerous three-way combination;
- Docker Sandboxes can be probed live for sandbox presence, host-filesystem separation and configured network decisions;
- agent-generated artifact checks are executable hooks, not screenshots;
- every evidence file is SHA-256 manifested and independently verifiable;
- JSON and standalone HTML reports are generated per run;
- the upstream `controls.yaml` can be fetched and hashed so draft drift cannot pass silently.

## Five-minute path

```bash
make install
make preflight
make demo
```

`make demo` is useful even before Docker Sandboxes is installed. Controls that require live `sbx` evidence will correctly report `MANUAL` rather than being faked.

To enable the live isolation vertical slice:

```bash
# Requires the Docker Sandboxes `sbx` CLI and sign-in.
make sandbox-create
make demo
make verify
```

The sandbox is created with a **sandbox-scoped deny** for `exfiltration.invalid`; no global policy is modified.

## Output

Each run creates:

```text
evidence/abl-<timestamp>/
├── inputs/assessment-config.yaml
├── controls/
│   ├── DIS-01/...
│   ├── CON-03/...
│   └── ...
├── assessment.json
└── manifest.sha256.json

reports/
├── abl-<timestamp>.json
└── abl-<timestamp>.html
```

Open the HTML report in a browser. Every implemented control states the evaluator used, summary, gaps and evidence paths. The displayed percentage is explicitly an **observed automated pass rate**, not a compliance score.

## Docker Sandboxes integration

V1 uses documented `sbx` surfaces:

- `sbx ls --json` to observe the target sandbox;
- `sbx policy ls <sandbox> --json` to capture active policy state;
- `sbx exec` for a safe host-filesystem canary test;
- `sbx policy check network --sandbox ...` for non-invasive allow/deny checks.

No secret is exfiltrated and no global access rule is changed by the assessor.

## Baseline drift

The Agent Baseline is still a draft. Before a customer-facing demo, run:

```bash
make baseline-sync
```

This fetches the authoritative upstream `whitepaper/controls.yaml`, stores it only in `.cache/`, hashes it, verifies the current 35 IDs, and reports ID drift. The official requirement text remains upstream.

## Architecture

```text
Agent declaration ───────┐
                         ├──► Evidence Engine ───► per-control results
Docker sbx live state ───┤                           │
                         │                           ▼
Artifact checks ─────────┘                    evidence bundle
                                                    │
                                            SHA-256 manifest
                                                    │
                                          JSON + HTML report
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/CONTROL_COVERAGE.md`](docs/CONTROL_COVERAGE.md), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`docs/EVIDENCE_MODEL.md`](docs/EVIDENCE_MODEL.md).

## Why the conservative statuses matter

A tool that says “Docker Sandbox present → CON-03 PASS” would create false confidence. CON-03 is broader than runtime isolation alone. V1 therefore gathers live evidence for the exact checks it implements and leaves broader gaps visible. The same rule applies everywhere else.

## Current limitations

The strongest missing layer is end-to-end action evidence: prompt/task → model → MCP gateway → policy decision → target-system result. MCP organization policies, just-in-time authority, credential revocation and full response playbooks are intentionally still `MANUAL`/`PARTIAL`. They are the next implementation milestone, not hidden assumptions.

## Upstream feedback

The public draft explicitly asks for implementation feedback. This lab will only submit feedback that emerges from reproducible implementation friction. See [`docs/UPSTREAM_FEEDBACK.md`](docs/UPSTREAM_FEEDBACK.md).

## License

Apache-2.0 for this repository's code. Agent Baseline materials remain under their upstream licenses and ownership; the authoritative control requirements are not vendored here.
