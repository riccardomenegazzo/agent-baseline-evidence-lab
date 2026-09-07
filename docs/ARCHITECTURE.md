# Architecture

The lab is an **evidence engine**, not a compliance scanner.

```text
                authoritative Agent Baseline
                           controls
                              │
                              ▼
   declared state ───► control catalogue ◄─── live Docker state
        YAML                   │                    sbx CLI
                               ▼
                         evaluator layer
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
       declared-state     live probes       manual gaps
        evaluators       (safe/read-only)      explicitly
             │                 │               surfaced
             └─────────────────┼─────────────────┘
                               ▼
                        evidence store
                  JSON/text + SHA-256 hashes
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
                JSON report           HTML report
```

## Design rules

1. **Never infer PASS from product presence.** Installing Docker Sandboxes is not evidence that every Agent Baseline control is satisfied.
2. **No hidden green defaults.** Unsupported controls become `MANUAL`, not `PASS`.
3. **Safe probes only.** V1 uses read-only inventory/policy queries and a disposable host canary file. It does not exfiltrate data or alter global policy.
4. **Evidence is run-scoped.** Every assessment receives a stable `run_id`; evidence is immutable-by-convention and SHA-256 manifested.
5. **Draft-aware.** The authoritative control requirements stay upstream. `abl sync-baseline` detects control-ID drift instead of silently redefining the baseline.

## V1 trust boundary

The evidence engine runs on the host. Docker Sandboxes is treated as the target execution boundary. The engine may invoke `sbx ls`, `sbx policy`, and `sbx exec` to collect evidence. A future adapter will ingest MCP gateway and organization-governance audit events so that Authorize and Observe can be assessed from end-to-end action traces.
