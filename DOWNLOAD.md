# Download Agent Baseline Evidence Lab

The recommended distribution channel is **GitHub Releases**.

## Latest release

Open:

https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/releases/latest

Current release, v0.10.0:

https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/releases/tag/v0.10.0

## Which file should I download?

For normal installation, download the Python wheel:

```text
agent_baseline_evidence_lab-0.10.0-py3-none-any.whl
```

The release also contains:

```text
agent_baseline_evidence_lab-0.10.0.tar.gz
SHA256SUMS
release-manifest.json
```

- `.whl` — recommended installable package;
- `.tar.gz` — source distribution;
- `SHA256SUMS` — integrity checksums;
- `release-manifest.json` — source commit, version, artifact sizes and SHA-256 digests.

GitHub additionally exposes standard source-code `.zip` and `.tar.gz` archives for the release tag.

## Install the wheel

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install ./agent_baseline_evidence_lab-0.10.0-py3-none-any.whl
abl --help
```

## Verify the downloaded artifacts

Download `SHA256SUMS` into the same directory as the wheel/source archive.

### macOS

```bash
shasum -a 256 -c SHA256SUMS
```

### Linux

```bash
sha256sum -c SHA256SUMS
```

You can also inspect `release-manifest.json` to confirm which Git commit produced the artifacts.

## Release lifecycle

A new release is published only after the `ci` workflow succeeds on `main` and the version in `pyproject.toml` has not already been published.

Published release assets are treated as immutable: the release workflow detects an existing tag/version and will not replace its artifacts.

To prepare the next version:

1. bump `[project].version` in `pyproject.toml`;
2. add `docs/releases/vX.Y.Z.md`;
3. merge/push the change to `main`;
4. after CI passes, GitHub Actions builds, smoke-tests and publishes the release automatically.

The release workflow can also be invoked manually or from a `v*` tag when needed.
