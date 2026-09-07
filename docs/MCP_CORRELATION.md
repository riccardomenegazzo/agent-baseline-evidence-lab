# MCP evaluation → execution correlation

Docker AI Governance audit records distinguish policy evaluations from execution outcomes. For MCP tool activity, the public schema documents:

- `tool_invocation` as a governance evaluation;
- `tool_execution` as the resulting execution outcome;
- a unique `audit_event_id` for each record;
- `audit_session_id` for the daemon session that produced the record;
- `resource_id`, `agent`, timestamp, category and decision metadata.

The public record reference does **not** document a per-action identifier that directly joins one `tool_invocation` record to its corresponding `tool_execution` record.

That distinction matters for Agent Baseline outcomes such as **OBS-02 End-to-end correlation** and **OBS-05 Intent-to-outcome evidence**. A collection of audit records is not automatically proof that a particular evaluated action produced a particular outcome.

## Lab model

`abl-mcp-correlate` uses a deliberately conservative heuristic:

1. same `audit_session_id`;
2. same `resource_id`;
3. same `agent` when both records contain an agent;
4. execution timestamp must be after the evaluation;
5. execution must occur within a configurable maximum time window;
6. the nearest matching later execution is selected once and cannot be reused by another evaluation.

Example:

```bash
abl-mcp-correlate \
  --agent codex \
  --audit-session-id <docker-session-id> \
  --max-gap-seconds 30 \
  --strict
```

The report contains:

- terminal allowed evaluations;
- terminal blocked evaluations;
- approval-required evaluations;
- paired allowed evaluations;
- unmatched allowed evaluations;
- orphan execution outcomes;
- pairing coverage;
- the exact matching basis;
- `confidence: heuristic` on every pair.

## Expected behavior for denied actions

A denied or rejected tool invocation is **not** expected to have a `tool_execution` record. Missing execution after `AUDIT_DECISION_DENY` or `AUDIT_DECISION_REJECTED` is therefore not treated as a correlation gap.

An allowed/approved invocation without a matching execution is a gap because the lab cannot prove its observed outcome. An execution without a compatible allowed/approved evaluation is also a gap because the lab cannot identify the governance decision that authorized it.

## Approval flows

`AUDIT_DECISION_APPROVAL_REQUIRED` is tracked separately from terminal allow/block decisions. It is evidence that consent was requested, not evidence that execution occurred. A later approved evaluation may be paired with an execution, but the current lab does not claim that the public schema provides a cryptographic or unique request binding across the full approval sequence.

## Why `complete` still does not mean "proven"

`complete: true` means every terminal allowed evaluation in the selected records found one compatible execution and no execution remained orphaned under the documented heuristic.

It does **not** upgrade the confidence from heuristic to deterministic. The report preserves this limitation even at 100% coverage.

## Assessment integration

When `assessment.docker_audit.enabled: true`, the evidence engine automatically writes:

```text
observations/docker-ai-governance-audit.json
observations/docker-mcp-correlation.json
```

and appends a `docker.mcp-correlation` event to the hash-chained assessment trace.

The HTML report surfaces:

- `MCP eval→execution pairs`;
- `MCP correlation: HEURISTIC COMPLETE | GAPS | NO MCP PAIRS`.

This makes missing observability visible instead of converting it into an optimistic PASS.

## Potential upstream feedback

The implementation suggests a concrete question for the Agent Baseline and/or audit producers:

> What evidence should be considered sufficient for OBS-02 when evaluation and execution records share a session, resource and timestamp proximity but the telemetry source does not expose a documented per-action correlation identifier?

A stronger producer-side primitive could be a stable action/request correlation identifier emitted on evaluation, approval and execution records. The lab should not submit this as upstream feedback until it is reproduced with real governed MCP traffic and the actual emitted Docker records are inspected.
