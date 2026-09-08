# Five-minute technical-manager demo

This walkthrough is designed for a Docker technical manager. It prioritizes customer problem, observed evidence, repeatability and claims boundaries over feature count.

## Before the call

```bash
make install
make preflight
make baseline-sync
make baseline-lock-verify
```

Optional but recommended before a live interview:

```bash
make signing-keygen
make baseline-lock-sign
make baseline-lock-verify-signature
```

The private key stays below `.abl/`, which is ignored by Git.

## The preferred demo

Community path:

```bash
make interview-demo
```

MCP / Docker AI Governance path, only when the required Docker capabilities are actually available:

```bash
make mcp-register-dhi
make interview-demo-mcp
```

Zero-mutation rehearsal:

```bash
make interview-demo-dry-run
```

After a real run, add authenticity and consolidated verification:

```bash
make sign-latest
make verify-signature-latest
make assurance-latest
```

---

## 0:00–0:30 — Frame the customer problem

> Security guidance for AI agents is easy to describe and hard to prove. I wanted to know whether a customer could take a real coding-agent run and answer a narrower question: for this agent, in this environment, during this run, what can we actually prove against the Agent Baseline?

Emphasize that this is a community implementation experiment, not an official Docker or Agent Baseline conformance product.

---

## 0:30–1:05 — Show the architecture

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
hash-chained trace + SHA-256 manifest
      │
      ├── JSON / HTML assessment
      └── run attestation
      │
      ▼
response drill
      │
      ├── verified sandbox stop
      ├── verified disposable binding removal
      ├── quarantine registry
      └── incident bundle
      │
      ▼
optional Ed25519 signature + post-run assurance
```

The key point:

> The engine never turns product presence into proof of a control.

---

## 1:05–1:55 — Run the real lifecycle

```bash
make interview-demo
```

The flow uses the exact unique sandbox created by the agent run. It assesses the result, performs the response drill, links immutable assessment and response evidence, records quarantine state, creates a digest-only incident bundle, verifies all postconditions and then removes only that disposable sandbox.

The live-run capsule stores by default:

- task SHA-256, not raw prompt;
- stdout/stderr SHA-256, not raw model output;
- disposable workspace before/after hashes;
- changed paths;
- exact sandbox identity;
- Docker Sandbox observations;
- artifact-validation results against the agent-modified workspace.

This is useful customer evidence without unnecessarily retaining developer prompt/output content.

---

## 1:55–2:35 — Show evidence, not a green dashboard

Open the generated HTML report and choose one `PARTIAL` or `MANUAL` control.

Good example:

> A Cedar policy describing tool scope or approval is design evidence. Unless I observe the relevant runtime decision, I do not promote that to full authorization proof.

Second example:

> A Docker audit session is not automatically the same thing as a business-task causal ID. I distinguish exact-marker evidence, bounded correlation and ambiguity instead of joining events because their timestamps overlap.

This credibility rule matters more than maximizing the green count.

---

## 2:35–3:15 — Show integrity, authenticity and their limits

Internal evidence verification:

```bash
make verify
```

Portable signature:

```bash
make sign-latest
make verify-signature-latest
```

Explain the distinction clearly:

> The SHA-256 manifest and hash chain detect evidence mutation. Ed25519 proves the signed bytes relative to a private key. Trust in the signer exists only if the verifier trusts the public key through an external channel.

Then run:

```bash
make assurance-latest
```

The assurance suite checks:

- assessment-bundle integrity;
- adversarial verifier regression matrix;
- credential-sensitive/code co-change;
- behavioral drift when a baseline exists;
- Ed25519 signature validity;
- whether an external public-key anchor is present;
- incident-bundle integrity;
- quarantine-registry integrity.

`FINDING` is deliberately different from `FAIL`: drift is something to investigate, while a corrupted evidence bundle or invalid signature is blocking.

---

## 3:15–3:50 — Show the adversarial trust model

The verification matrix demonstrates four different failure boundaries:

1. single-file mutation is detected internally;
2. trace truncation is detected internally;
3. a coordinated producer-side rewrite can remain internally self-consistent but is detected by an external anchor;
4. no exported artifact can prove an event that never entered the evidence pipeline.

The point is not offensive security. It is that every assurance claim has an explicit failure condition and a defined boundary.

---

## 3:50–4:25 — Show response as evidence

The real flow distinguishes:

```text
sandbox stop                               VERIFIED when observed
sandbox-scoped credential binding removal VERIFIED when observed
upstream provider token invalidation       NOT CLAIMED without provider evidence
quarantine decision                        RECORDED, not equated with network isolation
incident bundle                            DIGEST-VERIFIED
```

The original assessment is never rewritten after containment. Post-response evidence is linked by cryptographic digest instead.

The provider-revocation adapter is dry-run by default:

```bash
make provider-revocation-dry
```

This demonstrates fail-closed semantics without mutating a real credential.

---

## 4:25–4:45 — Optional MCP / Docker AI Governance evidence

Only show this section when the environment actually supports it.

```bash
make mcp-inventory-dhi
make mcp-oauth-status
make interview-demo-mcp
```

With a live sandbox:

```bash
make mcp-bypass-dhi SANDBOX=<sandbox-name>
```

The project intentionally separates:

- host-side MCP registration identity;
- OAuth authorization metadata;
- Cedar policy design;
- observed Docker governance decisions;
- direct sandbox network reachability.

A configured gateway is therefore not treated as proof that direct MCP access is impossible.

Audit correlation can be re-analyzed without rerunning the agent:

```bash
make audit-correlate-latest
```

Exact-evidence gate:

```bash
make audit-correlate-exact
```

---

## 4:45–5:00 — Close with the CXE-T angle

> I built this as a reusable customer PoC rather than a one-off demo: success criteria, explicit claims boundaries, live architecture validation, reproducible evidence, response testing, post-run assurance and a path for implementation feedback upstream. The part that interests me most is taking a recurring customer architecture question and turning it into an asset that can be reused, challenged and improved.

Then stop. Let the interviewer choose whether to drill into Docker Sandboxes, MCP, evidence integrity, policy design, response, auditability or the customer PoC model.

---

## Do not overclaim

Do not say:

- "Docker makes the Agent Baseline compliant";
- "this certifies an agent";
- "MCP Gateway proves authorization";
- "the evidence is tamper-proof";
- "a valid signature proves who the signer is";
- "one Docker audit_session_id proves task-level causality";
- "removing a sandbox credential binding invalidates the upstream provider token";
- "a quarantine registry entry means network quarantine happened".

Prefer:

- implementation assessment;
- observed evidence;
- partial coverage;
- exact-marker vs bounded correlation;
- tamper-evident bundle;
- portable Ed25519 signature;
- external public-key trust anchor;
- scoped credential-binding revocation;
- recorded quarantine decision;
- digest-verified incident bundle;
- reproducible customer PoC.
