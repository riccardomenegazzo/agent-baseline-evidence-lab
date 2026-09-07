.PHONY: install test lint preflight baseline-sync assess demo verify evidence-matrix audit-summary \
	live-dry-run live-demo live-demo-mcp mcp-register-dhi sandbox-create sandbox-run sandbox-shell sandbox-rm \
	response-drill response-drill-full response-drill-dry-run response-link response-link-verify \
	interview-demo interview-demo-mcp interview-demo-dry-run audit-correlate-latest audit-correlate-exact

VENV ?= .venv
PYTHON := $(VENV)/bin/python
ABL := $(VENV)/bin/abl

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

assess:
	$(ABL) assess --config examples/agent.yaml

demo: assess

verify:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(ABL) verify "$$latest"

# Reproducibly attack disposable copies of the latest verified bundle. Demonstrates
# integrity, truncation, coordinated-rewrite and never-emitted-event boundaries.
evidence-matrix:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.evidence_matrix "$$latest" \
		--output reports/evidence-verification-matrix.json

audit-summary:
	$(ABL) audit-summary

# Re-analyze finalized Docker AI Governance audit JSONL for the latest live agent session.
# Diagnostic mode reports exact/pending/ambiguous strength without failing on non-exact evidence.
audit-correlate-latest:
	@latest=$$(ls -1dt agent-runs/agent-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No agent run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.audit_correlation "$$latest/session.json"

# Same analysis, but act as a gate: exit non-zero unless resource_id contains the run marker.
audit-correlate-exact:
	@latest=$$(ls -1dt agent-runs/agent-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No agent run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.audit_correlation "$$latest/session.json" --require-exact

# CI-safe proof that the live-run capsule is metadata-only and internally verifiable.
live-dry-run:
	$(ABL) live-run --config examples/agent.yaml --task examples/task.md --dry-run --assess

# Community path: real Codex task in a disposable Docker Sandbox workspace.
live-demo:
	$(ABL) live-run --config examples/agent.yaml --task examples/task.md --assess

# Full MCP path. Register the public Docker Hardened Images MCP server once first.
mcp-register-dhi:
	sbx mcp add dhi --url https://dhi.io/mcp

live-demo-mcp:
	$(ABL) live-run --config examples/agent-mcp.yaml --task examples/task-mcp.md --assess --with-docker-audit

# Manager-facing end-to-end flow. Uses the unique sandbox created by the agent run,
# performs disposable credential-binding revocation + stop, links immutable evidence,
# verifies the link, then removes only that unique disposable sandbox.
interview-demo:
	$(PYTHON) -m agent_baseline_lab.interview_demo \
		--config examples/agent.yaml --task examples/task.md --cleanup

# MCP + Docker AI Governance audit variant. Register DHI first with `make mcp-register-dhi`.
# A run-scoped .invalid network marker is attempted to support empirical audit correlation.
interview-demo-mcp:
	$(PYTHON) -m agent_baseline_lab.interview_demo \
		--config examples/agent-mcp.yaml --task examples/task-mcp.md \
		--with-docker-audit --cleanup

# Full orchestration contract with zero sbx mutation and no positive response link.
interview-demo-dry-run:
	$(PYTHON) -m agent_baseline_lab.interview_demo \
		--config examples/agent.yaml --task examples/task.md --dry-run

# Explicit containment exercise. This affects only the named abl-demo sandbox.
response-drill:
	$(PYTHON) -m agent_baseline_lab.response --sandbox abl-demo --output .abl/response/abl-demo-stop.json

# Stronger response exercise: create a disposable sandbox-scoped custom credential binding,
# verify it exists, revoke it, verify it is gone, then stop only abl-demo.
response-drill-full:
	$(PYTHON) -m agent_baseline_lab.response --sandbox abl-demo \
		--output .abl/response/abl-demo-stop.json \
		--test-disposable-secret-revocation

# Link the latest verified assessment bundle to the verified response drill without
# mutating either artifact. Requires the full credential-binding drill by default.
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

# CI-safe contract check: writes evidence but executes no sbx mutation.
response-drill-dry-run:
	$(PYTHON) -m agent_baseline_lab.response --sandbox abl-demo --output .abl/response/abl-demo-stop-dry-run.json --dry-run --test-disposable-secret-revocation

# Lower-level sandbox helpers retained for manual exploration.
sandbox-create:
	sbx create --name abl-demo --deny-network exfiltration.invalid codex "$(CURDIR)/sample-app"

sandbox-run:
	sbx run codex --name abl-demo

sandbox-shell:
	sbx exec -it abl-demo bash

sandbox-rm:
	sbx rm abl-demo
