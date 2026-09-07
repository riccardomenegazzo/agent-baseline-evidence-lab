# Docker audit correlation

Docker AI Governance audit records provide strong event metadata, but `audit_session_id` identifies the sandbox **daemon session**, not an Agent Baseline task ID. This lab therefore does not treat a shared time window or a single daemon session as exact task correlation.

## Goal

Create an empirical bridge between:

```text
Agent Baseline live session
        │
        ▼
unique Docker Sandbox
        │
        ▼
run-scoped network marker
        │
        ▼
Docker governance evaluation
        │
        ▼
audit resource_id + audit_session_id
```

The bridge is considered exact only when the unique run marker is actually present in a finalized Docker audit record's `resource_id`.

## Correlation canary

For an audit-enabled interview flow, the lab derives a deterministic hostname from the agent session ID:

```text
abl-<20 hex chars>.correlation.invalid
```

The `.invalid` top-level domain is reserved for testing and is not intended to resolve to an external service.

The lab performs one bounded network attempt from the exact Docker Sandbox used by the live coding-agent run. It prefers `curl` and falls back to a Python socket if available. The expected outcome is **blocked or unreachable**; success is not required and is not the purpose of the probe.

The probe evidence stores:

- session ID;
- sandbox identity;
- marker hostname;
- whether the action was attempted;
- command return code;
- SHA-256 of stdout/stderr;
- expected network result.

It does not store raw prompt, agent output, credentials, or a successful external response.

## Evidence grades

| Strength | Meaning |
|---|---|
| `exact-marker` | At least one selected finalized Docker audit record has a `resource_id` containing the run-scoped marker. |
| `pending-finalization` | No finalized matching record is available, but Docker `.tmp` audit files are present. No negative conclusion is drawn. |
| `single-daemon-session` | The run window + agent filter yields one daemon `audit_session_id`, but the marker itself is not observed. Supporting evidence only. |
| `ambiguous-multi-session` | Multiple daemon sessions remain candidates in the selected window. |
| `no-observed-correlation` | No finalized selected record or candidate daemon session was observed. |
| `dry-run-no-correlation` | No marker action was executed; correlation cannot be claimed. |

Only `exact-marker` is a positive exact-correlation claim.

## Why `.tmp` is excluded

Docker local audit delivery writes in-progress records to `.tmp` and finalizes them into `.jsonl` through rotation. The lab follows the documented collection boundary and ingests finalized `.jsonl` only.

Therefore:

```text
.tmp exists + no selected JSONL record
```

means:

```text
pending-finalization
```

not:

```text
no governed event occurred
```

## Live manager path

The MCP / AI Governance interview flow automatically attempts the correlation canary:

```bash
make mcp-register-dhi
make interview-demo-mcp
```

The manager-facing summary prints the observed correlation strength and whether an exact marker was found.

When correlation evidence is produced during the run it is written as:

```text
.abl/correlation/<agent-session-id>.probe.json
reports/<assessment-run-id>.audit-correlation.json
```

## Re-analyze finalized records later

The agent-run capsule is immutable and contains the original session start time, agent identity and session ID. The marker is deterministically derived from that ID, so the audit analysis can be repeated without re-running the agent or mutating the original evidence bundle.

Diagnostic mode:

```bash
make audit-correlate-latest
```

This reports the best evidence grade and exits successfully even when the grade is pending or ambiguous.

Exact-correlation gate:

```bash
make audit-correlate-exact
```

This exits non-zero unless the marker is actually observed in finalized Docker audit `resource_id` evidence.

You can also point directly at a known audit directory or finalized JSONL file:

```bash
python -m agent_baseline_lab.audit_correlation \
  agent-runs/agent-.../session.json \
  --path /path/to/auditkit
```

## Claims boundary

The lab does **not** claim that:

- one `audit_session_id` proves every record belongs to one business task;
- overlapping timestamps establish causality;
- matching `agent=codex` alone identifies a unique coding task;
- a correlation marker proves authorization correctness;
- missing finalized audit evidence proves the action did not occur;
- a local policy log is equivalent to Docker AI Governance audit evidence.

The correlation canary improves evidence attribution; it does not change the meaning of the underlying governance decision.
