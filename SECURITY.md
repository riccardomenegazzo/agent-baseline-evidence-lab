# Security policy

## Scope

Agent Baseline Evidence Lab is a research and implementation-assessment project. Its adversarial scenarios are designed to be safe, bounded and non-destructive.

## Safety rules for probes

- Do not exfiltrate real credentials or secrets.
- Do not mutate organization-wide policy from an automated assessment.
- Prefer `sbx policy check` over making unnecessary outbound requests.
- Use synthetic canaries for filesystem-boundary tests.
- Scope any deny rule used by the demo to the named sandbox.
- Never interpret evaluator errors as passing evidence.

## Reporting a vulnerability

Please avoid publishing credentials, tokens, private traces or customer evidence in a public issue. Open a minimal report that describes the affected component and reproduction conditions without sensitive data.
