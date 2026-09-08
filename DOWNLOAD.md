# Download Agent Baseline Evidence Lab

The recommended distribution channel is **GitHub Releases**:

https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/releases/latest

## Which file should I download?

For normal installation, download the Python wheel whose version matches the release:

```text
agent_baseline_evidence_lab-<version>-py3-none-any.whl
```

Each automated release also contains:

```text
agent_baseline_evidence_lab-<version>.tar.gz
SHA256SUMS
release-manifest.json
```

- `.whl` — recommended installable package;
- `.tar.gz` — source distribution;
- `SHA256SUMS` — integrity checksums for the published artifacts;
- `release-manifest.json` — release version, source commit, artifact sizes and SHA-256 digests.

GitHub additionally exposes the standard source-code archives for the release tag.

## Install the wheel

After downloading the wheel:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install ./agent_baseline_evidence_lab-<version>-py3-none-any.whl
abl --help
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Verify the downloaded artifacts

Download `SHA256SUMS` into the same directory as the wheel and source archive.

### macOS

```bash
shasum -a 256 -c SHA256SUMS
```

### Linux

```bash
sha256sum -c SHA256SUMS
```

You can also inspect `release-manifest.json` to confirm which exact Git commit produced the package artifacts.

## What the release pipeline verifies

A release is published only after the main `ci` workflow succeeds. The release workflow then:

1. checks that the requested release version matches `pyproject.toml`;
2. refuses to overwrite an already-published version;
3. builds a wheel and source distribution;
4. records SHA-256 digests and source commit in `release-manifest.json`;
5. generates `SHA256SUMS`;
6. installs the wheel into a clean virtual environment;
7. smoke-tests the installed CLI;
8. publishes the GitHub Release assets.

Existing release assets are treated as immutable by the publisher.

## Preparing a future release

1. bump `[project].version` in `pyproject.toml`;
2. add `docs/releases/vX.Y.Z.md`;
3. push the change to `main`;
4. after CI passes, GitHub Actions builds, verifies and publishes the release automatically.

The workflow can also be invoked manually or from a `v*` tag when needed.
