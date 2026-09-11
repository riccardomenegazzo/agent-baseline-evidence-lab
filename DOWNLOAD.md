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
- `release-manifest.json` — version, tag, source commit, artifact sizes, SHA-256 digests and release-provenance metadata.

Starting with the first release after v0.10.2, GitHub Artifact Attestations also provide SLSA build provenance for the wheel, source distribution and release metadata.

## Install the wheel

After downloading the wheel, use Python 3.11 or newer:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install ./agent_baseline_evidence_lab-<version>-py3-none-any.whl
abl init my-evidence-lab
cd my-evidence-lab
abl-trust --dry-run --scout-mode off
abl-present --open
```

Starting with v0.17.0, the wheel contains all assets for this walkthrough: community/MCP configurations, tasks, sample application and tests, Dockerfile checks and policy examples. No Git checkout or Make installation is needed.

`abl init` creates a **new** directory and generates a local signing keypair. It refuses any existing destination, including an empty directory or symlink. No keys are distributed with the wheel. Installation may download dependencies; workspace initialization itself is offline.

Run the subsequent commands from the initialized directory. Expected output is `DRY_RUN`, with artifact verification `NOT_RUN` and lineage `false`. It validates orchestration and signed handoff handling, not live enforcement.

Key handling and rotation: [Signing Keys](docs/SIGNING_KEYS.md). Reproducible customer demonstration: [Customer Walkthrough](docs/CUSTOMER_WALKTHROUGH.md).

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Verify the downloaded artifacts

For a high-assurance download, use both verification layers.

### 1. Verify SHA-256 integrity

Download `SHA256SUMS` into the same directory as the wheel, source archive and `release-manifest.json`.

macOS:

```bash
shasum -a 256 -c SHA256SUMS
```

Linux:

```bash
sha256sum -c SHA256SUMS
```

Then inspect `release-manifest.json` to confirm the exact Git commit associated with the package artifacts.

### 2. Verify SLSA build provenance

With GitHub CLI installed:

```bash
gh attestation verify \
  agent_baseline_evidence_lab-<version>-py3-none-any.whl \
  --repo riccardomenegazzo/agent-baseline-evidence-lab
```

You can run the same command for:

```text
agent_baseline_evidence_lab-<version>.tar.gz
release-manifest.json
SHA256SUMS
```

The release workflow performs this verification itself before publishing the release.

See [`docs/RELEASE_PROVENANCE.md`](docs/RELEASE_PROVENANCE.md) for the exact trust and claims boundary.

## What the release pipeline verifies

A release is published only after the main `ci` workflow succeeds. The release workflow then:

1. checks that the requested release version matches `pyproject.toml`;
2. requires matching release notes under `docs/releases/`;
3. refuses to overwrite an already-published version;
4. builds a wheel and source distribution;
5. records artifact size, SHA-256 and source commit in `release-manifest.json`;
6. generates `SHA256SUMS`;
7. installs the wheel into a clean virtual environment;
8. smoke-tests the entrypoints, creates a workspace outside the checkout and runs the complete dry-run and signed presentation from the installed wheel;
9. creates GitHub/Sigstore-backed SLSA build provenance attestations for all four release files;
10. runs `gh attestation verify` against every release file;
11. publishes the immutable GitHub Release only if all preceding gates pass.

Existing release assets are treated as immutable by the publisher.

## What provenance does — and does not — mean

A successful GitHub artifact-attestation verification supports a bounded provenance claim: the downloaded subject is linked to an attestation associated with the expected GitHub repository/workflow identity.

It does **not** prove that:

- the software is vulnerability-free;
- every upstream dependency is safe;
- the repository owner has a particular real-world identity;
- the package is compliance-certified;
- the artifact is appropriate for a specific production environment.

The project treats provenance as evidence, not certification.

## Preparing a future release

1. complete and verify the implementation on `main`;
2. add `docs/releases/vX.Y.Z.md`;
3. bump `[project].version` in `pyproject.toml` as the final content change;
4. push to `main`;
5. let the main CI gate the release workflow;
6. verify the release artifact attestations and immutable assets.

The workflow can also be invoked manually or from a `v*` tag when needed, but the same version and release-note checks still apply.

