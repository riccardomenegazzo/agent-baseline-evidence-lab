# Control coverage

This matrix describes **what the current implementation can actually evidence**, not what Docker, MCP servers, AI agents, or surrounding enterprise products may be capable of.

Two evidence phases are intentionally separated:

1. **assessment-time evidence** — immutable evidence collected before response actions;
2. **post-run evidence** — response, quarantine, incident, signing, drift and assurance artifacts linked without rewriting the original assessment.

That separation prevents containment actions from retroactively changing the state that was assessed.

## Assessment-time coverage

| Outcome | Evidence-producing implementation | Intentionally incomplete / bounded |
|---|---|---|
| Discover | DIS-01..06 declared-state checks; DIS-04 component registry; optional Docker MCP inventory observation | DIS-07 continuous cross-system reconciliation; runtime composition beyond observed sources |
| Constrain | CON-01 admission prerequisites; CON-02 toxic-combination detector; CON-03 live Docker Sandboxes host-canary + network-policy probes; CON-04 capability-profile evidence | deployment admission enforcement; complete resource/process/duration confinement; org governance when unavailable |
| Authorize | AUT-01 Docker audit attribution when observed; AUT-02/AUT-05/AUT-06 Docker MCP Cedar analysis | JIT credentials, delegation attenuation, step-up, PoP and independent approval remain incomplete without direct authority evidence |
| Observe | OBS-01 normalized trace coverage; OBS-02 stable run correlation; OBS-05 intent/result mapping; OBS-06 hash-chain + file-manifest integrity | strict external causality, source completeness, retention/access-control/legal-hold guarantees |
| Validate | VAL-01 executable safe adversarial scenarios; VAL-03 executable artifact checks against the agent-modified workspace | full first-party component validation; business-outcome validation; exhaustive agent-specific threat coverage |
| Respond | RES controls can consume declared/tested playbook hooks during assessment | real containment evidence is intentionally produced after the immutable assessment, not injected back into it |

## Supplemental and post-run evidence

These capabilities exist in the repository but are **not automatically promoted into the pre-response assessment result** unless the relevant evaluator has direct evidence at assessment time.

| Capability | Implemented evidence | Boundary |
|---|---|---|
| MCP registration identity | `sbx mcp` inventory with expected name/URL matching | configuration presence does not prove invocation or enforcement |
| MCP dynamic-tool restriction | Cedar analysis distinguishes `invokePrimordial` permit vs forbid | static policy posture does not prove runtime decision |
| MCP governance chain | bounded evaluation → approval/deny → execution analyzer | no request-level causal ID is invented when the source data does not provide one |
| Direct MCP bypass | sandbox network reachability probe to the remote MCP host | gateway governance and direct outbound traffic are separate surfaces |
| OAuth state | metadata-only `sbx mcp auth status` adapter with recursive secret-field redaction | authorization-state observation is not token disclosure or upstream revocation proof |
| OBS-03 drift | retained baseline comparison for event types, destinations and MCP targets | a change is a finding, not automatically malicious behavior |
| OBS-04 unintended action | changed-path detector for credential-sensitive + code co-change | file contents and secrets are not read |
| Evidence integrity | adversarial verifier matrix covering mutation, truncation and coordinated rewrite | internal consistency cannot prove a source event that was never emitted |
| Completeness | external completeness-witness reconciliation | completeness depends on an independent source/checkpoint expectation |
| Authenticity | Ed25519 signature over exact artifact bytes | signature validity is distinct from external signer identity |
| Baseline trust | source digest/control-ID/version/status/drift lock + verifier + optional signature | signature is meaningful only after lock/source consistency is verified |
| Stop circuit breaker | exact sandbox stop with observed postcondition | command success alone is insufficient |
| Credential binding revocation | disposable sandbox-scoped binding observed before and absent after removal | local removal does not prove provider token/session invalidation |
| Provider revocation | explicit fail-closed adapter, dry-run by default | server-side invalidation is claimed only with provider evidence |
| Quarantine | append-only component quarantine decision registry | registry entry records a decision; it does not itself enforce network isolation |
| Incident preservation | digest-only incident manifest linking assessment/response/correlation/quarantine artifacts | preserves linkage and integrity, not root-cause correctness |
| Non-agent fallback | reviewer/reason/validation-command evidence with no AI agent required | does not claim the reviewer inspected every line unless separate evidence exists |
| Schema evolution | known migrations with future-schema rejection | migration can never create a new positive security claim |
| Post-run assurance | consolidated blocking verifier + non-blocking findings | PASS is not official Agent Baseline conformance |

## Why controls remain PARTIAL or MANUAL

The project deliberately refuses to infer a control from a nearby capability. Examples:

- an MCP Gateway existing in the environment does not prove independent approval;
- a Cedar policy file does not prove the corresponding runtime decision happened;
- a Docker audit session does not automatically prove business-task causality;
- a stopped sandbox does not prove every upstream credential was invalidated;
- a valid signature does not establish who owns the key;
- a valid hash chain does not prove a source event was emitted in the first place.

The intended result is a lower green count but a stronger evidence story.
