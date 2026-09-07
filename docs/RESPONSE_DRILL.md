# Response drill

The response drill is an **explicit destructive test** for one named Docker Sandbox. It is separate from `abl assess` on purpose: an assessment must never stop a developer sandbox as a side effect.

## Claims

The drill separates two claims that are often conflated:

1. **Containment** — the named sandbox was stopped and a structured post-stop state was observed.
2. **Credential-binding revocation** — a disposable, sandbox-scoped Docker custom-secret binding was created, observed, removed, and independently observed as absent afterwards.

The second claim does **not** prove that a real provider token was invalidated at GitHub, OpenAI, AWS, or another upstream identity provider. It proves that the tested Docker Sandbox no longer has the scoped proxy credential binding created by this drill.

## Basic containment drill

```bash
make response-drill
```

This affects only `abl-demo` and writes:

```text
.abl/response/abl-demo-stop.json
```

The command fails unless the stop command succeeds **and** the sandbox is subsequently observed in a stopped-like structured state.

## Full disposable-credential drill

```bash
make response-drill-full
```

Before stopping `abl-demo`, the lab:

1. creates a uniquely named custom secret binding scoped to `abl-demo`;
2. uses a host-side command to generate random disposable secret material;
3. never stores the generated secret in the response evidence;
4. lists sandbox-scoped secrets and verifies the unique placeholder is present;
5. removes only that placeholder from only `abl-demo`;
6. lists secrets again and verifies the placeholder is absent;
7. stops only `abl-demo` and verifies its post-stop state.

The custom secret uses the reserved test destination `credential-drill.invalid` and environment variable `ABL_DRILL_TOKEN`. No outbound request is made to that destination.

## Why dynamic disposable material

The drill intentionally does not accept a real API key. Docker Sandboxes supports host-side dynamic secret sources via `--command`; the lab uses that mechanism to generate random material that exists only for the scope of the test. The response artifact records command outcomes and the non-secret placeholder, never the generated secret.

## Verify the artifact

Containment only:

```bash
python3 -m agent_baseline_lab.response_verify \
  .abl/response/abl-demo-stop.json \
  --sandbox abl-demo
```

Containment plus scoped credential-binding revocation:

```bash
python3 -m agent_baseline_lab.response_verify \
  .abl/response/abl-demo-stop.json \
  --sandbox abl-demo \
  --require-revocation
```

The verifier emits the SHA-256 of the response artifact so the result can be pinned or correlated with another evidence bundle.

## CI-safe mode

```bash
make response-drill-dry-run
```

Dry-run mode performs no `sbx` mutation and is required to report both:

```text
verified_stopped = false
credential_revocation_tested = false
```

CI asserts this behavior to prevent a metadata-only exercise from ever being promoted to evidence of containment or revocation.

## Safety boundary

The drill never:

- removes all sandboxes;
- removes global secrets;
- modifies a real OpenAI/GitHub/provider credential;
- claims upstream token invalidation;
- runs automatically as part of `abl assess`;
- treats command success alone as proof of the postcondition.
