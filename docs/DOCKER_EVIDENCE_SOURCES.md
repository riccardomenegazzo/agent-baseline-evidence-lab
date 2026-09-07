# Docker evidence sources

This document records the exact Docker surfaces the lab is designed around and, equally importantly, what each source **does not prove**.

## Docker Sandboxes inventory and policy

| Evidence | Command | What it proves | What it does not prove |
|---|---|---|---|
| sandbox inventory | `sbx ls --json` | target sandbox is observable | isolation quality by itself |
| active policy | `sbx policy ls <sandbox> --json` | policy state returned by sandbox daemon | that every intended action was evaluated |
| network decision | `sbx policy check network --sandbox <name> <target>` | current policy decision for target | actual packet/result telemetry |
| policy log | `sbx policy log <sandbox> --json` | recent policy log data | full org audit history |
| command execution | `sbx exec <sandbox> ...` | command ran in target sandbox | a control beyond the exact probe |

Docker reference:
- https://docs.docker.com/reference/cli/sbx/
- https://docs.docker.com/reference/cli/sbx/policy/
- https://docs.docker.com/ai/sandboxes/security/defaults/

## MCP Gateway and Cedar policies

The lab analyzes Cedar policy design against Docker's current MCP policy model:

- `register`
- `invokeTool`
- `invokePrimordial`
- `readResource`
- `getPrompt`

Relevant Docker references:
- https://docs.docker.com/ai/sandboxes/mcp-gateway/
- https://docs.docker.com/ai/sandboxes/governance/access-controls/mcp/
- https://docs.docker.com/ai/sandboxes/governance/reference/mcp-policy/

### Important claims boundary

A static policy file proves policy **design evidence**, not live organization enforcement. The evaluator therefore remains `PARTIAL` until live governance/audit evidence is joined.

`@requireApproval` is treated as an MCP in-session confirmation guardrail. It is not treated as proof of independent administrator approval or separation of duties.

## Docker AI Governance local audit logs

When AI Governance local audit delivery is enabled, Docker documents JSONL records that include:

- `audit_event_id`
- `timestamp`
- `category`
- `decision`
- user/org identity metadata
- `audit_session_id`
- `resource_id`
- `action_type`
- `agent` when known

Action types include network and filesystem evaluations, tool invocation, resource reads, server registration and execution outcomes.

References:
- https://docs.docker.com/ai/sandboxes/governance/audit/
- https://docs.docker.com/ai/sandboxes/governance/audit/local/
- https://docs.docker.com/ai/sandboxes/governance/audit/record-reference/

The lab reads finalized `.jsonl` only and ignores `.tmp` files because Docker documents `.tmp` as incomplete/in-progress.

### Privacy behavior

Before audit records are persisted in the evidence directory, these fields are replaced with run-scoped SHA-256 pseudonyms:

- `username`
- `user_email`
- `org_id`
- `org_name`
- `hostname`

This preserves within-run equality/correlation without storing the original values in the generated evidence bundle.

### Correlation boundary

Docker's `audit_session_id` identifies the sandbox daemon audit session; the lab's `run_id` identifies the assessment run. They are not assumed to be equivalent. A selected `audit_session_id` substantially strengthens attribution, but does not on its own bind an event to the declared business intent or task delegation.
