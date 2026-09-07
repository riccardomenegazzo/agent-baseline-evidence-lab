.PHONY: install test lint preflight baseline-sync assess demo verify audit-summary sandbox-create sandbox-run sandbox-shell sandbox-rm

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

# Creates a detached Codex sandbox with a deliberately denied canary destination.
# The deny is sandbox-scoped and does not modify global policy.
sandbox-create:
	sbx create --name abl-demo --deny-network exfiltration.invalid codex "$(CURDIR)/sample-app"

sandbox-run:
	sbx run codex --name abl-demo

sandbox-shell:
	sbx exec -it abl-demo bash

sandbox-rm:
	sbx rm abl-demo
