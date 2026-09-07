# Upstream feedback log

This log records only **implementation-derived** observations. It is not a place to advertise this repository.

## 2026-09-08 — OBS-06: internal integrity is not independent verifiability

**Related upstream discussion:** `agentbaseline/agentbaseline#26` — *OBS-06 and VAL: nothing requires the evidence to be checkable by someone who does not trust the operator*.

### What the implementation exposed

The lab originally produced two integrity mechanisms:

1. a SHA-256 manifest covering every evidence file; and
2. an append-only hash-chained trace ledger.

Those mechanisms detect ordinary mutation **only while the verifier trusts the bundle boundary**. An actor able to rewrite the evidence, recompute the manifest, and rebuild the trace chain can still manufacture a self-consistent bundle.

That means a statement such as `manifest verified` must not be interpreted as proof of authenticity or independent verifiability.

### Implementation response

The project now separates three claims:

- **internal consistency** — manifest hashes match current files;
- **tamper evidence inside the exported run** — trace-chain linkage verifies;
- **external trust** — requires a digest anchored outside the bundle or a future cryptographic signer.

Assessment runs additionally emit an **unsigned in-toto-style run attestation**. It binds the evidence-manifest digest to:

- Agent Baseline version;
- assessment run ID and configuration digest;
- trace head and event count;
- control-result vector digest;
- coding-agent session and Docker Sandbox identity;
- task digest without persisting the prompt;
- workspace pre/post root digests;
- stdout/stderr digests without persisting output by default; and
- Docker AI Governance audit summary when available.

The attestation explicitly records `signed: false` and `externalTrustAnchorRequiredForAuthenticity: true`.

### Why this matters to OBS-06

This implementation supports the concern raised in upstream issue #26: **integrity protection and independent verification are different properties**.

A practical test for OBS-06 should therefore distinguish at least:

1. alteration detection inside an evidence package;
2. omission/completeness claims;
3. authenticity of the package origin; and
4. independent verification using material not controlled by the evidence producer.

### Evidence in this repository

- `src/agent_baseline_lab/evidence.py` — manifest and trace verification boundary;
- `src/agent_baseline_lab/trace.py` — hash-chained event ledger;
- `src/agent_baseline_lab/provenance.py` — run attestation and explicit unsigned claim boundary;
- `tests/test_provenance.py` — assertion that authenticity is not claimed without an external trust anchor.

No new upstream issue is proposed because #26 already captures the underlying gap. If implementation feedback is requested there, this project can provide a concrete reproducible example rather than a duplicate proposal.
