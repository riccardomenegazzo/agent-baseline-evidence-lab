# V1 control coverage

This matrix describes **what the current implementation can actually evidence**, not what the surrounding products may be capable of.

| Outcome | Automated / evidence-producing in V1 | Explicitly incomplete |
|---|---|---|
| Discover | DIS-01..06 declared-state checks; DIS-04 component schema | DIS-07 continuous reconciliation |
| Constrain | CON-01 admission prerequisites; CON-02 toxic-combination detector; CON-03 live Docker Sandboxes probe; CON-04 capability-profile evidence | deployment admission enforcement; emergent capability-graph analysis; organization governance when unavailable |
| Authorize | none promoted to PASS yet | identity/action attribution, JIT credentials, approvals, step-up, delegation and PoP need end-to-end authority evidence |
| Observe | OBS-02 run/task correlation envelope; OBS-06 SHA-256 evidence manifest | model/MCP/target-system trace joining, drift, unintended-action detection, evidence lifecycle controls |
| Validate | VAL-01 scenario-plan evidence + CON-03 live probes; VAL-03 executable artifact checks | complete adversarial orchestration, first-party component suite, business-outcome validation |
| Respond | declared/testable response playbook hooks for RES controls | real credential revocation, quarantine registry and tested fallback workflows |

## Why several controls remain MANUAL

The project deliberately refuses to infer a control from a nearby capability. For example, an MCP Gateway existing in the environment does not prove independent approval, just-in-time authority, or end-to-end attribution. Those controls remain `MANUAL` until the lab can ingest the relevant policy decision and downstream outcome evidence.
