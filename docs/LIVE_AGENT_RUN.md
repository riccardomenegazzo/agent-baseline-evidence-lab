# Live agent run

The `live-run` path turns the lab from an offline assessment into an observed coding-agent exercise.

It is intentionally designed around a data-minimizing evidence model: the task prompt and agent output are **not** persisted by default. The evidence capsule stores hashes, byte counts, timing, Docker/Sandbox metadata and workspace content hashes instead.

## Community path

Prerequisites:

- Docker Sandboxes (`sbx`)
- Codex authentication stored by Docker Sandboxes
- Python 3.11+

One-time authentication:

```bash
sbx secret set openai --oauth
```

Run:

```bash
make live-demo
```

The lab:

1. copies `sample-app/` to a disposable `.abl-workspaces/<session>/workspace`;
2. creates a uniquely named Docker Sandbox for Codex;
3. adds only the configured sandbox-scoped network denies;
4. runs the task from `examples/task.md`;
5. captures Docker Sandbox/policy observations;
6. hashes the before/after workspace trees and records changed paths;
7. imports the metadata-only execution capsule into an Agent Baseline assessment;
8. runs artifact checks against **the agent-modified disposable workspace**;
9. creates the assessment evidence bundle and HTML/JSON report;
10. removes the sandbox unless `--keep-sandbox` was requested.

Docker's Codex integration runs Codex inside the Docker Sandbox boundary. Docker documents the default Codex startup as `codex --dangerously-bypass-approvals-and-sandbox`; this disables Codex's nested sandbox because Docker Sandbox is the outer isolation boundary. The lab does not treat that flag as evidence of safety by itself.

## Full MCP path: Docker Hardened Images

Docker exposes the DHI catalog as a remote MCP server at `https://dhi.io/mcp`. Most DHI query tools are public and need no DHI credentials.

Register it once:

```bash
make mcp-register-dhi
```

Then run:

```bash
make live-demo-mcp
```

The MCP demo uses:

- `examples/agent-mcp.yaml`;
- `examples/task-mcp.md`;
- static MCP mode with the registered server name `dhi`;
- `policies/mcp/dhi-readonly.cedar` as the organization-policy reference posture.

The task asks Codex to consult DHI through the Docker Sandboxes MCP Gateway and write a small recommendation file based only on MCP-observed data.

## Governance boundary

The Cedar files in this repository are **not installed automatically** into Docker AI Governance. They are reference/design evidence.

For runtime MCP enforcement, an administrator must configure the corresponding organization MCP policy in Docker AI Governance. With organization governance active, governed MCP activity is default-deny unless a matching `permit` allows it; a matching `forbid` overrides permits.

The DHI demo policy intentionally:

- permits registration only as `dhi` and only for `https://dhi.io/mcp`;
- permits only read-only DHI tools;
- forbids non-read-only DHI tool calls;
- forbids local-stdio server registration;
- forbids dynamic `mcp-add` and `code-mode` expansion.

## Audit correlation

With Docker AI Governance local audit delivery enabled:

```bash
abl live-run \
  --config examples/agent-mcp.yaml \
  --task examples/task-mcp.md \
  --assess \
  --with-docker-audit
```

The generated assessment config narrows audit ingestion to:

- `agent=codex`;
- the live-run start/end time window.

Docker audit records are metadata-only and can include evaluation/execution categories such as network egress, filesystem access, MCP tool invocation and MCP tool execution. Identity/organization/hostname fields are pseudonymized before the lab persists them.

Local Docker audit files rotate asynchronously. Therefore zero records in an immediate run is **not** treated as proof that no governed activity occurred; it remains a missing-evidence condition.

## Data handling

Default live-run evidence contains:

- prompt SHA-256 and byte count;
- redacted command representation;
- stdout/stderr SHA-256 and byte counts;
- no raw prompt;
- no raw agent output;
- before/after workspace file hashes;
- changed path names;
- Docker Sandbox/policy metadata.

Use `--capture-output` only when raw agent stdout/stderr is explicitly acceptable for the environment being tested.

## CI path

CI never starts a real agent. It runs:

```bash
abl live-run --config examples/agent.yaml --task examples/task.md --dry-run --assess
```

This validates capsule generation, prompt redaction, disposable workspace behavior, assessment ingestion and evidence integrity without requiring Docker credentials or network access.
