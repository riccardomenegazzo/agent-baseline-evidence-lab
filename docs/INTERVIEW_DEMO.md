# Five-minute technical demo

This demo is designed for a technical manager. It prioritizes the problem, evidence and limitations over feature count.

## 0:00–0:30 — Frame the problem

> Security guidance for AI agents is easy to describe and hard to prove. I wanted to know whether a customer could take a real coding-agent run and answer a narrower question: for this agent, in this environment, during this run, what can we actually prove against the Agent Baseline?

Emphasize that the project is a community implementation experiment, not an official Docker or Agent Baseline conformance tool.

## 0:30–1:10 — Show the architecture

Open the README architecture diagram and explain the evidence sources:

```text
Agent Baseline controls
        │
        ▼
Evidence Engine
   ├── declared state
   ├── Docker sbx probes
   ├── MCP Cedar policy analysis
   ├── adversarial scenarios
   ├── Docker AI Governance audit metadata
   └── artifact tests
        │
        ▼
hash-chained trace + evidence manifest
        │
        ├── JSON/HTML assessment
        └── run attestation
```

The key point is that the engine never treats product presence as proof of a control.

## 1:10–2:10 — Run a real coding-agent task

Preflight:

```bash
abl preflight
```

Live Codex path:

```bash
abl live-run \
  --config examples/agent.yaml \
  --task examples/task.md \
  --assess
```

For the MCP vertical slice use `examples/agent-mcp.yaml` after registering the documented DHI MCP endpoint.

Explain what is captured by default:

- task SHA-256, not raw prompt;
- agent stdout/stderr SHA-256, not raw output;
- disposable workspace before/after root hashes;
- changed-path set;
- Docker Sandbox identity and policy observations;
- optional Docker AI Governance audit metadata;
- resulting Agent Baseline assessment.

## 2:10–2:55 — Show evidence, not a green dashboard

Open the generated HTML report.

Call out at least one `PARTIAL` or `MANUAL` control and explain why it is not promoted to `PASS`.

Recommended example:

> A Cedar file describing approval or tool scope is design evidence. Unless I observe the policy being enforced in the relevant execution, I do not call that full authorization proof.

This is the project's most important credibility rule.

## 2:55–3:40 — Verify integrity and provenance

Verify the exported evidence bundle:

```bash
abl verify evidence/abl-...
```

Then verify the run attestation:

```bash
abl verify-attestation \
  reports/abl-....attestation.json \
  evidence/abl-.../manifest.sha256.json
```

Explain the trust boundary:

> This proves internal consistency and binds the exported manifest to the observed run facts. It is intentionally unsigned. Authenticity requires an external digest anchor today; I did not want to call a self-recomputed hash a signature.

If useful, mention that this implementation experience maps directly to the concern raised in Agent Baseline issue #26 around independently verifiable evidence.

## 3:40–4:15 — Show the adversarial mindset

Point to the scenario runner and negative provenance test:

- host-canary separation;
- network-policy decision checks;
- MCP-policy contract scenario;
- mutated-manifest attestation verification failure.

The point is not offensive security. It is that each claim has an expected failure condition.

## 4:15–4:45 — Show response as evidence, not a playbook

Only do this against the disposable `abl-demo` sandbox.

```bash
make response-drill-full
make response-link
```

Explain the two independent postconditions:

```text
sandbox stop                              VERIFIED
sandbox-scoped credential binding removal VERIFIED
upstream provider token invalidation       NOT CLAIMED
```

The full drill creates a unique disposable custom-secret binding only for `abl-demo`, observes it, removes it, observes that it is gone, and then verifies that only `abl-demo` reaches a stopped state. No real OpenAI, GitHub, or other provider credential is modified.

`make response-link` does **not** rewrite the original assessment bundle. It creates a third unsigned statement whose subjects are the SHA-256 digest of the original assessment manifest and the SHA-256 digest of the response artifact. This gives a clean evidence timeline:

```text
assessment run ──► immutable bundle
                       │
incident drill ──► response evidence
                       │
                       ▼
                response-link statement
```

This is the strongest `Respond` story in the demo: the project distinguishes a written response procedure from an observed containment/revocation postcondition.

## 4:45–5:00 — Close with the CXE-T angle

> I built this as a reusable customer PoC rather than a one-off demo: success criteria, explicit claims boundaries, evidence collection, repeatable validation, a real response drill and a path for implementation feedback upstream. The interesting part to me is turning a recurring customer architecture question into an asset that can be reused and improved.

Then stop and let the interviewer choose which area to drill into.

## Do not overclaim

Do not say:

- "Docker makes the Agent Baseline compliant";
- "this certifies an agent";
- "MCP Gateway proves authorization";
- "the evidence is tamper-proof";
- "the in-toto-style statement is signed";
- "removing a sandbox credential binding invalidates the upstream provider token".

Prefer:

- implementation assessment;
- observed evidence;
- partial coverage;
- tamper-evident bundle;
- unsigned run attestation;
- scoped credential-binding revocation;
- external trust anchor;
- reproducible customer PoC.
