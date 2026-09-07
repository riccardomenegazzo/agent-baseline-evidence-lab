# Five-minute technical demo

This walkthrough is designed for a Docker technical manager. It prioritizes customer problem, observed evidence, repeatability and claims boundaries over feature count.

## Before the call

Install and validate the local environment:

```bash
make install
make preflight
make baseline-sync
```

The preferred community demo is now a single command:

```bash
make interview-demo
```

It runs a real Codex task in a unique Docker Sandbox, assesses the resulting environment, performs a disposable response drill against **that exact sandbox**, links response evidence to the immutable assessment, independently verifies the link, and removes only the unique disposable sandbox.

For the MCP / Docker AI Governance variant:

```bash
make mcp-register-dhi
make interview-demo-mcp
```

Use the MCP variant only when the required Docker capabilities are available. The community path is sufficient to explain the architecture without pretending paid governance evidence exists.

## 0:00–0:30 — Frame the problem

> Security guidance for AI agents is easy to describe and hard to prove. I wanted to know whether a customer could take a real coding-agent run and answer a narrower question: for this agent, in this environment, during this run, what can we actually prove against the Agent Baseline?

Emphasize that this is a community implementation experiment, not an official Docker or Agent Baseline conformance product.

## 0:30–1:05 — Show the architecture

Open the README architecture diagram:

```text
real coding task
      │
      ▼
Codex + unique Docker Sandbox
      │
      ▼
Agent Baseline Evidence Engine
   ├── declared state
   ├── sbx boundary probes
   ├── MCP Cedar analysis
   ├── adversarial scenarios
   ├── optional Docker audit metadata
   └── artifact checks
      │
      ▼
hash-chained trace + manifest
      │
      ├── JSON/HTML assessment
      └── unsigned run attestation
      │
      ▼
response drill
      │
      ▼
assessment SHA ─┐
                ├── verified response-link
response SHA ───┘
```

The key point:

> The engine never turns product presence into proof of a control.

## 1:05–1:55 — Show a real run

Run:

```bash
make interview-demo
```

The final summary should make the lifecycle visible:

```text
INTERVIEW EVIDENCE FLOW
  session:             agent-...
  sandbox:             abl-demo-...
  assessment run:      abl-...
  bundle verified:     True
  stop verified:       True
  credential revoked:  True (Docker sandbox binding)
  response link:       True
  cleanup succeeded:   True
  HTML report:         ...
```

Explain what the live-run capsule records by default:

- task SHA-256, not raw prompt;
- stdout/stderr SHA-256, not raw model output;
- disposable workspace before/after content hashes;
- changed-path set;
- actual unique sandbox identity;
- Docker Sandbox policy observations;
- result of artifact checks against the **agent-modified workspace**.

This is useful customer evidence without unnecessarily persisting developer prompt/output content.

## 1:55–2:40 — Show evidence, not a green dashboard

Open the generated HTML report.

Select one `PARTIAL` or `MANUAL` control and explain why it did not become `PASS`.

Recommended example:

> A Cedar file describing approval or tool scope is design evidence. Unless I observe the relevant policy decision during execution, I do not call that full authorization proof.

A second useful example:

> A Docker audit daemon session is not automatically a business-task ID. I distinguish bounded correlation from exact correlation rather than joining events because their timestamps happen to overlap.

This credibility rule is more important than maximizing the green count.

## 2:40–3:20 — Verify integrity and provenance

Verify the evidence bundle:

```bash
abl verify evidence/abl-...
```

Verify the run attestation:

```bash
abl verify-attestation \
  reports/abl-....attestation.json \
  evidence/abl-.../manifest.sha256.json
```

Explain:

> This verifies internal consistency and binds the exported manifest to observed run facts. The statement is intentionally unsigned. I do not call a self-recomputed hash a signature; authenticity needs an external trust anchor.

The trace is append-only and SHA-256 hash-chained. The file bundle has a separate SHA-256 manifest.

## 3:20–3:50 — Show the adversarial mindset

Point to the executable scenarios:

- host-canary filesystem separation;
- network-policy decision checks;
- MCP policy contract validation;
- agent-generated artifact tests;
- negative provenance tests where evidence mutation must cause verification failure.

The point is not offensive security. It is that every claim should have an explicit failure condition.

## 3:50–4:25 — Show response as evidence, not a playbook

The single-command flow already performed the response exercise on the exact unique sandbox created for that run.

The two separate postconditions are:

```text
sandbox stop                               VERIFIED
sandbox-scoped credential binding removal VERIFIED
upstream provider token invalidation       NOT CLAIMED
```

The drill creates random disposable secret material through a host-side command, binds it only to the run sandbox, verifies the placeholder exists, removes only that binding, verifies it is absent, and then independently verifies the sandbox reached a stopped state.

No real OpenAI, GitHub, AWS or other provider credential is used.

Then show the response link:

```text
assessment manifest SHA-256 ──┐
                              ├── response-link statement
response evidence SHA-256 ────┘
```

The original assessment is never rewritten after containment. `response-link-verify` recomputes both digests, validates the assessment bundle, checks the run ID and trace head, re-verifies response claims, and fails on mismatch.

## 4:25–4:45 — Optional: show Docker audit correlation

Only use this section when running with Docker AI Governance audit delivery:

```bash
make interview-demo-mcp
```

The lab generates a deterministic run-scoped hostname under `.correlation.invalid` and performs one bounded network attempt from the exact sandbox. It then looks for that marker in finalized Docker audit `resource_id` evidence.

Possible outputs are deliberately graded:

```text
exact-marker
pending-finalization
single-daemon-session
ambiguous-multi-session
no-observed-correlation
```

Only `exact-marker` means the marker was actually observed in the Docker audit resource.

If finalized JSONL was not yet available during the demo, the exact same immutable agent session can be re-analyzed later without rerunning the agent:

```bash
make audit-correlate-latest
```

To use it as an exact-evidence gate:

```bash
make audit-correlate-exact
```

See [`AUDIT_CORRELATION.md`](AUDIT_CORRELATION.md).

## 4:45–5:00 — Close with the CXE-T angle

> I built this as a reusable customer PoC rather than a one-off demo: success criteria, explicit claims boundaries, live architecture validation, reproducible evidence, response testing and a path for implementation feedback upstream. The part that interests me most is taking a recurring customer architecture question and turning it into an asset that can be reused, challenged and improved.

Then stop. Let the interviewer choose whether to drill into Docker Sandboxes, MCP, evidence integrity, policy design, auditability or the customer PoC model.

## Do not overclaim

Do not say:

- "Docker makes the Agent Baseline compliant";
- "this certifies an agent";
- "MCP Gateway proves authorization";
- "the evidence is tamper-proof";
- "the in-toto-style statement is signed";
- "one Docker audit_session_id proves task-level causality";
- "removing a sandbox credential binding invalidates the upstream provider token".

Prefer:

- implementation assessment;
- observed evidence;
- partial coverage;
- exact-marker vs bounded correlation;
- tamper-evident bundle;
- unsigned run attestation;
- scoped credential-binding revocation;
- external trust anchor;
- reproducible customer PoC.
