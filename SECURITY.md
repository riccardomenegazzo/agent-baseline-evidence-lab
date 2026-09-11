# Security Policy

## Supported versions

Security fixes are applied to the **latest published release** and the current `main` branch. Older pre-1.0 releases are research snapshots and are not maintained as long-term support branches.

## Project security boundary

Agent Baseline Evidence Lab is a research and implementation-assessment project. It executes local evidence collection, safe adversarial probes and optional Docker tooling against environments explicitly selected by the operator.

The project is **not** a general-purpose penetration-testing framework. Its scenarios are designed to be bounded, attributable and non-destructive.

## Probe safety rules

Contributions and built-in probes must follow these rules:

- never exfiltrate real credentials, tokens or customer secrets;
- use synthetic canaries for filesystem-boundary tests;
- prefer policy decision checks over unnecessary outbound traffic;
- never mutate organization-wide policy from a normal assessment;
- scope any mutable demo action to an explicitly named disposable resource;
- never interpret evaluator exceptions, missing tools or unavailable telemetry as passing evidence;
- never persist raw authentication material merely to make an evidence artifact more complete;
- fail closed when a claimed postcondition cannot be verified;
- keep dry-run paths incapable of manufacturing live containment, revocation or enforcement claims.

## Sensitive evidence

Generated `evidence/`, `agent-runs/`, `reports/` and `.abl/` content may contain environment-specific metadata. Review artifacts before publishing them.

The default customer-pack path is designed to minimize local path leakage and exclude private signing keys, but operators remain responsible for deciding whether a particular evidence bundle is appropriate to share.

Never commit `.abl/` signing keys, real provider credentials, customer evidence or raw audit data containing sensitive information.

## Reporting a vulnerability

Please do **not** publish credentials, tokens, private traces, customer evidence or a weaponized reproduction in a public issue.

If GitHub Private Vulnerability Reporting is available for this repository, use the repository **Security** tab. Otherwise, open a minimal public issue describing only the affected component and request a private coordination channel; do not include sensitive reproduction material in that issue.

Useful reports include:

- affected release / commit;
- affected module or verifier;
- expected security boundary;
- observed boundary violation;
- minimal non-sensitive reproduction conditions;
- whether evidence integrity, confidentiality or false-positive claims are affected.

## High-priority vulnerability classes

The following are especially important for this project:

- private-key or credential leakage into portable packs;
- path traversal / symlink extraction issues;
- verifier bypass allowing tampered evidence to validate;
- schema migration that manufactures a positive claim;
- dry-run or evaluator error incorrectly becoming `PASS`;
- signature subject confusion or key-selection bypass;
- command construction that expands the intended scope of a bounded probe.

## Disclosure principle

A security fix must preserve the project's central evidence contract: **do not hide an uncertainty by turning it into a positive assertion.**


## Local signing keys

From v0.17.0, key generation refuses existing files and symlinks. New private keys use mode `0600` on POSIX and newly created key directories use `0700`. These are filesystem permissions, not encryption at rest or hardware-backed protection; Windows access control depends on the user's directory ACLs.

Older keys are not automatically rewritten. Protect retained private keys and keep old public verification keys when rotating. See [Signing Keys](docs/SIGNING_KEYS.md) for the procedure and compatibility limits.

Signing metadata is limited to 64 KiB per document. Verification requires schema version 1 as an integer, unique JSON fields, valid key/signature encodings and key-ID continuity. Missing files, malformed metadata and unknown versions return a failed verification. The supplied external key must match the embedded public key. This validates a signature relative to a key, not the identity or authorization of its owner.
