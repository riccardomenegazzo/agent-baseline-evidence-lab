# Local signing keys

The default workflow uses `.abl/keys/attestation-private.json` and `.abl/keys/attestation-public.json`. `abl init` creates a new pair locally. The private key must remain private; provide the public key to a verifier through a channel they already trust.

## Creation and existing workspaces

To create a pair manually in a repository checkout:

```bash
python -m agent_baseline_lab.signing keygen
```

The command fails if either destination exists, including a symlink. It never repairs an incomplete pair by replacing the surviving key. Restore the matching pair or choose new filenames. Signature output must also differ from the signed subject and private key, including hard-link aliases.

On Linux/macOS, new private files are created with mode `0600` before any private bytes are written. Newly created key directories use `0700`. Existing keys and directory permissions are not changed implicitly. Protect keys created by older versions explicitly:

```bash
chmod 700 .abl/keys
chmod 600 .abl/keys/attestation-private.json
```

These permissions do not encrypt a key or provide a hardware trust anchor. On Windows, use a private user directory and appropriate ACLs.

## Rotation without losing old verification material

Generate the replacement under new paths:

```bash
python -m agent_baseline_lab.signing keygen \
  --private .abl/keys/next/attestation-private.json \
  --public .abl/keys/next/attestation-public.json
```

For individual artifacts, explicitly select the replacement private key with `sign --private` and its public key with `verify --public`. Old artifacts continue to verify with the old public key. A new key does not retroactively authenticate evidence signed by the old one.

To select the replacement for future `abl-trust` runs, after the preceding keygen succeeds, run this while no other flow is using the workspace:

```bash
python - <<'PY'
from pathlib import Path
from agent_baseline_lab.signing import validate_keypair

keys = Path('.abl/keys')
private_name = 'attestation-private.json'
public_name = 'attestation-public.json'
old_id = validate_keypair(keys / private_name, keys / public_name)
new_id = validate_keypair(keys / 'next' / private_name, keys / 'next' / public_name)
if old_id == new_id:
    raise SystemExit('Replacement key must be different')
archive = keys / 'archive' / old_id.removeprefix('ed25519:')
archive.mkdir(mode=0o700, parents=True, exist_ok=False)
for name in (private_name, public_name):
    (keys / name).rename(archive / name)
for name in (private_name, public_name):
    (keys / 'next' / name).rename(keys / name)
print('Previous verification material retained at:', archive)
PY
```

This explicit maintenance procedure is not a transaction across process interruption: if interrupted, restore the matching pair from the retained paths before running a flow. Never combine keys from different generations. Protect archived private keys under the same access policy as current ones; retain at least their public counterparts for historical verification.

Existing live runs record the default public-key path. After rotation, that path points to the new key, so `abl-present` correctly rejects their old signatures. Verify an older handoff explicitly with its archived public key, or keep each generation in a separate workspace:

```bash
python -m agent_baseline_lab.signing verify \
  reports/<old-run>.customer-trust-handoff.zip \
  reports/<old-run>.customer-trust-handoff.zip.ed25519.json \
  --public .abl/keys/archive/<old-key-id>/attestation-public.json
```

Re-sign the baseline lock with the selected new key before the next live flow. Distribute the replacement public key through the same trusted process used for the original. Rotation does not revoke an exposed key for recipients automatically.

## Verification contract

The verifier accepts version 1 signing metadata, checks unique JSON fields and bounded input size, validates Ed25519 key/signature lengths and recomputes key IDs. External verification also requires the embedded key to match the supplied public key. Unknown versions and malformed or missing inputs fail verification rather than producing a traceback or a positive result.

The signature authenticates the exact subject bytes. Its `subject_path` is an informational label, so moving or renaming an artifact does not invalidate it. Signer identity, authorization, telemetry completeness and production approval remain outside this cryptographic check.
