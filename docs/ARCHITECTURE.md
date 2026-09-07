# Architecture

The lab is an **evidence engine**, not a compliance scanner.

```text
                    authoritative Agent Baseline
                          v1.0-draft IDs
                                │
                                ▼
                     ┌─────────────────────┐
 declared YAML ─────►│   control catalogue │
                     └──────────┬──────────┘
                                ▼
                     ┌─────────────────────┐
                     │   evaluator layer   │
                     └──────┬────┬────┬────┘
                            │    │    │
             ┌──────────────┘    │    └────────────────┐
             ▼                   ▼                     ▼
      Docker `sbx`         Cedar analysis        artifact checks
      live probes           + scenarios          + playbooks
             │                   │                     │
             └──────────────┬────┴───────────────┬─────┘
                            │                    │
                            ▼                    ▼
                    normalized lab trace    optional Docker
                    SHA-256 hash chain      AI Governance JSONL
                            ▲                    │
                            └──────────┬─────────┘
                                       ▼
                                evidence store
                           per-control + observations
                                       │
                          ┌────────────┴────────────┐
                          ▼                         ▼
                 SHA-256 file manifest        assessment.json
                          │                    trace anchors
                          └────────────┬────────────┘
                                       ▼
                                  JSON + HTML
```

## Design rules

1. **Never infer PASS from product presence.** A feature being installed is not evidence for the whole control.
2. **No hidden green defaults.** Unsupported checks become `MANUAL`; unexecuted live scenarios become `SKIP` inside VAL-01 evidence.
3. **Safe probes by default.** Network decisions use policy evaluation rather than arbitrary outbound traffic. Host-canary files are disposable.
4. **Declared versus observed state stays separate.** The report does not pretend a YAML declaration is effective runtime authority.
5. **Evidence is run-scoped.** Every assessment gets a `run_id`, a trace and a file manifest.
6. **External telemetry is normalized, not silently trusted.** Docker audit events retain their own `audit_session_id` and source timestamp.
7. **Privacy before persistence.** User/org/host audit identity fields are pseudonymized before writing evidence.
8. **Draft-aware.** The authoritative Agent Baseline requirement text stays upstream; the lab tracks IDs and source drift.

## Trace design

The lab writes one NDJSON event per normalized action. Each event includes a `prev_event_hash`, and the current `event_hash` is SHA-256 over canonical JSON for the rest of the event.

Docker audit events are appended as `docker.audit` events with original `audit_event_id`, `audit_session_id`, category, source timestamp, schema version and agent in attributes. They are not rewritten to look like native lab events.

## Trust anchors

Three local anchors protect internal consistency:

- per-file SHA-256 manifest;
- trace hash chain;
- final trace head + event count recorded in `assessment.json`.

`abl verify` may additionally accept expected manifest/trace-head hashes from an external system. Digital signatures are a roadmap item.

## Docker boundary

The evidence engine runs on the host. Docker Sandboxes is the target execution boundary. The engine only invokes documented `sbx` surfaces and stores command outputs as evidence.

Docker AI Governance audit ingestion is optional. It is a separate evidence source and is not required for the open/community path.

## Live execution capsule

V0.4 adds a separate agent execution capsule before assessment:

```text
public task file
     │ hash only in evidence
     ▼
disposable workspace copy
     │
     ▼
Docker Sandbox ── Codex ── optional static DHI MCP Gateway
     │                         │
     │                         └── optional AI Governance audit metadata
     ▼
workspace before/after hashes + changed paths
     │
     ▼
metadata-only agent-run capsule + SHA-256 manifest
     │
     ▼
assessment import
     │
     ├── agent.task.started/completed trace events
     ├── Docker audit events when available
     ├── artifact tests against modified workspace
     └── Agent Baseline control evaluation
```

The execution capsule and assessment bundle are deliberately separate trust domains: the assessment verifies the imported capsule manifest before using it as evidence. A corrupted capsule is treated as an evidence-integrity problem rather than being silently trusted.
