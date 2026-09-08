.PHONY: install test lint preflight baseline-sync baseline-lock-verify baseline-lock-sign \
	assess demo verify evidence-matrix audit-summary audit-correlate-latest audit-correlate-exact \
	live-dry-run live-demo live-demo-mcp mcp-register-dhi mcp-runtime-dhi mcp-runtime-dry-run \
	mcp-action-chains mcp-bypass-dry-run mcp-oauth-dry-run mcp-oauth-revoke \
	drift-baseline-latest drift-check-latest unintended-latest \
	response-drill response-drill-full response-drill-dry-run response-link response-link-verify \
	fallback-demo quarantine-latest incident-latest incident-verify-latest \
	trust-keygen sign-latest verify-latest-signature rekor-dry-run rekor-publish-latest \
	interview-demo interview-demo-mcp interview-demo-dry-run v07-dry-run \
	sandbox-create sandbox-run sandbox-shell sandbox-rm

VENV ?= .venv
PYTHON := $(VENV)/bin/python
ABL := $(VENV)/bin/abl
MCP_SERVER ?= dhi
SANDBOX ?= abl-demo
SIGNING_KEY ?= .abl/keys/evidence_ed25519
BASELINE_CACHE ?= .cache/agentbaseline

install:
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install -U pip
	$(PYTHON) -m pip install -e '.[dev]'

test:
	$(PYTHON) -m pytest
	python3 -m unittest discover -s sample-app/tests -v

lint:
	$(VENV)/bin/ruff check src tests scripts sample-app

preflight:
	$(ABL) preflight

baseline-sync:
	$(ABL) sync-baseline

baseline-lock-verify:
	$(PYTHON) -m agent_baseline_lab.baseline_lock verify $(BASELINE_CACHE)

baseline-lock-sign:
	$(PYTHON) -m agent_baseline_lab.baseline_lock sign $(BASELINE_CACHE) --private-key $(SIGNING_KEY)

assess:
	$(ABL) assess --config examples/agent.yaml

demo: assess

verify:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(ABL) verify "$$latest"

evidence-matrix:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.evidence_matrix "$$latest" \
		--output reports/evidence-verification-matrix.json

audit-summary:
	$(ABL) audit-summary

audit-correlate-latest:
	@latest=$$(ls -1dt agent-runs/agent-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No agent run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.audit_correlation "$$latest/session.json"

audit-correlate-exact:
	@latest=$$(ls -1dt agent-runs/agent-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No agent run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.audit_correlation "$$latest/session.json" --require-exact

live-dry-run:
	$(ABL) live-run --config examples/agent.yaml --task examples/task.md --dry-run --assess

live-demo:
	$(ABL) live-run --config examples/agent.yaml --task examples/task.md --assess

mcp-register-dhi:
	sbx mcp add dhi --url https://dhi.io/mcp

live-demo-mcp:
	$(ABL) live-run --config examples/agent-mcp.yaml --task examples/task-mcp.md --assess --with-docker-audit

mcp-runtime-dhi:
	$(PYTHON) -m agent_baseline_lab.mcp_runtime collect dhi \
		--expect dhi=https://dhi.io/mcp --output reports/mcp-runtime-dhi.json

mcp-runtime-dry-run:
	$(PYTHON) -m agent_baseline_lab.mcp_runtime collect dhi \
		--expect dhi=https://dhi.io/mcp --output reports/mcp-runtime-dry-run.json --dry-run

mcp-action-chains:
	$(PYTHON) -m agent_baseline_lab.mcp_runtime chains \
		--agent codex --output reports/mcp-action-chains.json

mcp-bypass-dry-run:
	$(PYTHON) -m agent_baseline_lab.mcp_bypass \
		--sandbox $(SANDBOX) --server-url https://dhi.io/mcp \
		--policy policies/mcp/dhi-readonly.cedar \
		--output reports/mcp-direct-bypass-dry-run.json --dry-run

# Safe contract path: no credential mutation.
mcp-oauth-dry-run:
	$(PYTHON) -m agent_baseline_lab.mcp_oauth_revocation $(MCP_SERVER) \
		--output reports/mcp-oauth-revocation-dry-run.json --dry-run

# Explicitly mutating path. This removes only Docker-hosted OAuth credentials for MCP_SERVER.
mcp-oauth-revoke:
	$(PYTHON) -m agent_baseline_lab.mcp_oauth_revocation $(MCP_SERVER) \
		--output reports/mcp-oauth-revocation-$(MCP_SERVER).json --confirm

drift-baseline-latest:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	mkdir -p .abl/drift; \
	$(PYTHON) -m agent_baseline_lab.drift create "$$latest/trace/events.ndjson" \
		--profile-id known-good --output .abl/drift/known-good.json

drift-check-latest:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.drift compare .abl/drift/known-good.json \
		"$$latest/trace/events.ndjson" --output reports/behavior-drift.json

unintended-latest:
	@latest=$$(ls -1dt agent-runs/agent-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No agent run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.unintended "$$latest/session.json" \
		--output reports/unintended-action.json

interview-demo:
	$(PYTHON) -m agent_baseline_lab.interview_demo \
		--config examples/agent.yaml --task examples/task.md --cleanup

interview-demo-mcp:
	$(PYTHON) -m agent_baseline_lab.interview_demo \
		--config examples/agent-mcp.yaml --task examples/task-mcp.md \
		--with-docker-audit --cleanup

interview-demo-dry-run:
	$(PYTHON) -m agent_baseline_lab.interview_demo \
		--config examples/agent.yaml --task examples/task.md --dry-run

response-drill:
	$(PYTHON) -m agent_baseline_lab.response --sandbox abl-demo --output .abl/response/abl-demo-stop.json

response-drill-full:
	$(PYTHON) -m agent_baseline_lab.response --sandbox abl-demo \
		--output .abl/response/abl-demo-stop.json \
		--test-disposable-secret-revocation

response-link:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No assessment evidence run found"; exit 1; fi; \
	run_id=$$(basename "$$latest"); \
	$(PYTHON) -m agent_baseline_lab.response_link \
		"$$latest" .abl/response/abl-demo-stop.json \
		--sandbox abl-demo --require-revocation \
		--output "reports/$${run_id}.response-link.json"

response-link-verify:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No assessment evidence run found"; exit 1; fi; \
	run_id=$$(basename "$$latest"); \
	$(PYTHON) -m agent_baseline_lab.response_link_verify \
		"reports/$${run_id}.response-link.json" \
		"$$latest" .abl/response/abl-demo-stop.json

response-drill-dry-run:
	$(PYTHON) -m agent_baseline_lab.response --sandbox abl-demo \
		--output .abl/response/abl-demo-stop-dry-run.json --dry-run \
		--test-disposable-secret-revocation

fallback-demo:
	$(PYTHON) -m agent_baseline_lab.fallback \
		--command-json '["python3","-m","unittest","discover","-s","sample-app/tests","-v"]' \
		--cwd . --output reports/non-agent-fallback.json

quarantine-latest:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.quarantine quarantine $(SANDBOX) \
		--type sandbox --reason "operator-directed evidence drill" \
		--actor operator --evidence "$$latest/manifest.sha256.json"

incident-latest: fallback-demo
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.incident build "$$latest" \
		--fallback reports/non-agent-fallback.json --output-root incidents

incident-verify-latest:
	@latest=$$(ls -1dt incidents/incident-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No incident bundle found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.incident verify "$$latest"

trust-keygen:
	@mkdir -p $$(dirname $(SIGNING_KEY)); \
	$(PYTHON) -m agent_baseline_lab.signing keygen $(SIGNING_KEY) \
		--identity agent-baseline-evidence-lab

sign-latest:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.signing sign "$$latest/manifest.sha256.json" \
		--private-key $(SIGNING_KEY) --identity agent-baseline-evidence-lab

verify-latest-signature:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.signing verify \
		"$$latest/manifest.sha256.json.signature.json"

rekor-dry-run:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.rekor "$$latest/manifest.sha256.json" \
		--signature "$$latest/manifest.sha256.json.sig" \
		--public-key $(SIGNING_KEY).pub \
		--output reports/rekor-dry-run.json --dry-run

# Explicit external side effect: publishes the signed manifest to the configured public Rekor log.
rekor-publish-latest:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.rekor "$$latest/manifest.sha256.json" \
		--signature "$$latest/manifest.sha256.json.sig" \
		--public-key $(SIGNING_KEY).pub \
		--output reports/rekor-receipt.json

# Exercises every v0.7 non-destructive contract. No Docker or OAuth mutation, no Rekor publication.
v07-dry-run: live-dry-run mcp-runtime-dry-run mcp-bypass-dry-run mcp-oauth-dry-run \
	interview-demo-dry-run evidence-matrix fallback-demo incident-latest

sandbox-create:
	sbx create --name abl-demo --deny-network exfiltration.invalid codex "$(CURDIR)/sample-app"

sandbox-run:
	sbx run codex --name abl-demo

sandbox-shell:
	sbx exec -it abl-demo bash

sandbox-rm:
	sbx rm abl-demo
