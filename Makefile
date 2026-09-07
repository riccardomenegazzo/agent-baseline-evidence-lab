.PHONY: install test lint preflight baseline-sync assess demo verify audit-summary \
	live-dry-run live-demo live-demo-mcp mcp-register-dhi sandbox-create sandbox-run sandbox-shell sandbox-rm \
	response-drill response-drill-full response-drill-dry-run

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

audit-summary:
	$(ABL) audit-summary

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

# Explicit containment exercise. This affects only the named abl-demo sandbox.
response-drill:
	$(PYTHON) -m agent_baseline_lab.response --sandbox abl-demo --output .abl/response/abl-demo-stop.json

# Stronger response exercise: create a disposable sandbox-scoped custom credential binding,
# verify it exists, revoke it, verify it is gone, then stop only abl-demo.
response-drill-full:
	$(PYTHON) -m agent_baseline_lab.response --sandbox abl-demo \
		--output .abl/response/abl-demo-stop.json \
		--test-disposable-secret-revocation

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
