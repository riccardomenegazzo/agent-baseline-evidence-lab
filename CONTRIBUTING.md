# Contributing

Contributions should improve the quality of evidence or the honesty of an assessment.

## Rules

- Never map product presence directly to `PASS`.
- Every automated evaluator needs a unit test and a documented evidence artifact.
- Destructive probes, credential exfiltration, or unscoped policy mutation are out of scope.
- If an upstream requirement cannot be proven, return `PARTIAL` or `MANUAL`.
- Keep the official control text upstream; this repository stores only IDs/titles plus implementation mappings.

Run `make test` and `make lint` before submitting changes.
