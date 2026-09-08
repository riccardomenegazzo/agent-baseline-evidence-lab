.PHONY: install test lint preflight readiness readiness-mcp baseline-sync baseline-lock-verify baseline-lock-sign baseline-lock-verify-signature \
	assess demo verify assurance-latest evidence-matrix customer-pack customer-pack-verify audit-summary \
	live-dry-run live-demo live-demo-mcp mcp-register-dhi mcp-inventory-dhi mcp-bypass-dhi mcp-oauth-status \
	sandbox-create sandbox-run sandbox-shell sandbox-rm \
	response-drill response-drill-full response-drill-dry-run response-link response-link-verify \
	interview-demo interview-demo-mcp interview-demo-dry-run golden-demo golden-demo-mcp golden-demo-dry-run \
	audit-correlate-latest audit-correlate-exact signing-keygen sign-latest verify-signature-latest \
	drift-baseline drift-compare unintended-latest fallback-demo quarantine-latest incident-bundle-latest \
	provider-revocation-dry

VENV ?= .venv
PYTHON := $(VENV)/bin/python
ABL := $(VENV)/bin/abl
SANDBOX ?= abl-demo
MCP_HOST ?= dhi.io
MCP_SERVER ?= dhi
BASELINE_CACHE ?= .cache/agentbaseline
CUSTOMER_PACK ?= reports/customer-evidence-pack.zip

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

readiness:
	$(PYTHON) -m agent_baseline_lab.readiness \
		--profile community --baseline-cache "$(BASELINE_CACHE)" \
		--output reports/readiness-community.json

readiness-mcp:
	$(PYTHON) -m agent_baseline_lab.readiness \
		--profile mcp --baseline-cache "$(BASELINE_CACHE)" \
		--output reports/readiness-mcp.json

baseline-sync:
	$(ABL) sync-baseline --cache "$(BASELINE_CACHE)"

baseline-lock-verify:
	$(PYTHON) -m agent_baseline_lab.baseline "$(BASELINE_CACHE)"

baseline-lock-sign: baseline-lock-verify
	@if [ ! -f .abl/keys/attestation-private.json ]; then echo "Run make signing-keygen first"; exit 1; fi
	$(PYTHON) -m agent_baseline_lab.signing sign \
		"$(BASELINE_CACHE)/baseline.lock.json" \
		--private .abl/keys/attestation-private.json \
		--output "$(BASELINE_CACHE)/baseline.lock.ed25519.json"

baseline-lock-verify-signature: baseline-lock-verify
	$(PYTHON) -m agent_baseline_lab.signing verify \
		"$(BASELINE_CACHE)/baseline.lock.json" \
		"$(BASELINE_CACHE)/baseline.lock.ed25519.json" \
		--public .abl/keys/attestation-public.json

assess:
	$(ABL) assess --config examples/agent.yaml

demo: assess

verify:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(ABL) verify "$$latest"

assurance-latest:
	$(PYTHON) -m agent_baseline_lab.assurance_suite \
		--output reports/assurance-summary.json

evidence-matrix:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.evidence_matrix "$$latest" \
		--output reports/evidence-verification-matrix.json

customer-pack: assurance-latest
	$(PYTHON) -m agent_baseline_lab.portable_pack create \
		--output "$(CUSTOMER_PACK)"

customer-pack-verify:
	@if [ ! -f "$(CUSTOMER_PACK)" ]; then echo "Customer evidence pack not found: $(CUSTOMER_PACK)"; exit 1; fi
	$(PYTHON) -m agent_baseline_lab.portable_pack verify "$(CUSTOMER_PACK)"

signing-keygen:
	$(PYTHON) -m agent_baseline_lab.signing keygen \
		--private .abl/keys/attestation-private.json \
		--public .abl/keys/attestation-public.json

sign-latest:
	@latest=$$(ls -1t reports/abl-*.attestation.json 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No run attestation found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.signing sign "$$latest" \
		--private .abl/keys/attestation-private.json \
		--output "$${latest}.ed25519.json"

verify-signature-latest:
	@latest=$$(ls -1t reports/abl-*.attestation.json 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No run attestation found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.signing verify "$$latest" \
		"$${latest}.ed25519.json" --public .abl/keys/attestation-public.json

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

mcp-inventory-dhi:
	$(PYTHON) -m agent_baseline_lab.mcp_inventory \
		--expect dhi=https://dhi.io/mcp \
		--output reports/mcp-inventory.json

mcp-bypass-dhi:
	$(PYTHON) -m agent_baseline_lab.mcp_bypass \
		--sandbox "$(SANDBOX)" --host "$(MCP_HOST)" \
		--output reports/mcp-bypass.json

mcp-oauth-status:
	$(PYTHON) -m agent_baseline_lab.oauth_state "$(MCP_SERVER)" \
		--output reports/mcp-oauth-status.json

drift-baseline:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.drift create "$$latest/trace/events.ndjson" \
		--output .abl/baselines/behavior.json

drift-compare:
	@latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No evidence run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.drift compare .abl/baselines/behavior.json \
		"$$latest/trace/events.ndjson" --output reports/behavior-drift.json

unintended-latest:
	@latest=$$(ls -1dt agent-runs/agent-* 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "No agent run found"; exit 1; fi; \
	$(PYTHON) -m agent_baseline_lab.unintended_action \
		"$$latest/workspace-changes.json" --output reports/unintended-action.json

fallback-demo:
	$(PYTHON) -m agent_baseline_lab.fallback \
		--workspace sample-app --reviewer demo-human-reviewer \
		--reason "agent disabled for fallback exercise" \
		--command "python3 -m unittest discover -s tests -v" \
		--output reports/fallback.json

quarantine-latest:
	@response=$$(ls -1t .abl/response/*.json 2>/dev/null | head -1); \
	latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$response" ] || [ -z "$$latest" ]; then echo "Response/evidence missing"; exit 1; fi; \
	run_id=$$(basename "$$latest"); \
	sandbox=$$($(PYTHON) -c 'import json,sys; print(json.load(open(sys.argv[1]))["sandbox"])' "$$response"); \
	$(PYTHON) -m agent_baseline_lab.quarantine add \
		--component-type sandbox --component-id "$$sandbox" \
		--reason "verified response containment" --run-id "$$run_id" \
		--response-evidence "$$response"

incident-bundle-latest:
	@assessment=$$(ls -1t reports/abl-*.json 2>/dev/null | grep -v -E 'attestation|response-link|interview-demo' | head -1); \
	response=$$(ls -1t .abl/response/*.json 2>/dev/null | head -1); \
	latest=$$(ls -1dt evidence/abl-* 2>/dev/null | head -1); \
	if [ -z "$$assessment" ] || [ -z "$$response" ] || [ -z "$$latest" ]; then echo "Required evidence missing"; exit 1; fi; \
	run_id=$$(basename "$$latest"); \
	$(PYTHON) -m agent_baseline_lab.incident_bundle create \
		--output "reports/$${run_id}.incident.json" --run-id "$$run_id" \
		--artifact "assessment=$$assessment" --artifact "response=$$response" \
		--artifact "quarantine-registry=.abl/quarantine/registry.ndjson"

provider-revocation-dry:
	$(PYTHON) -m agent_baseline_lab.provider_revocation docker-mcp-oauth dhi \
		--output reports/provider-revocation-dry.json

live-dry-run:
	$(ABL) live-run --config examples/agent.yaml --task examples/task.md --dry-run --assess

live-demo:
	$(ABL) live-run --config examples/agent.yaml --task examples/task.md --assess

mcp-register-dhi:
	sbx mcp add dhi --url https://dhi.io/mcp

live-demo-mcp:
	$(ABL) live-run --config examples/agent-mcp.yaml --task examples/task-mcp.md --assess --with-docker-audit

interview-demo: readiness
	$(PYTHON) -m agent_baseline_lab.interview_demo \
		--config examples/agent.yaml --task examples/task.md --cleanup

interview-demo-mcp: readiness-mcp
	$(PYTHON) -m agent_baseline_lab.interview_demo \
		--config examples/agent-mcp.yaml --task examples/task-mcp.md \
		--with-docker-audit --cleanup

interview-demo-dry-run:
	$(PYTHON) -m agent_baseline_lab.interview_demo \
		--config examples/agent.yaml --task examples/task.md --dry-run

# Preferred manager-facing lifecycle. The live variants fail closed unless the
# baseline has been synced, signed and the local Docker prerequisites verify.
golden-demo:
	$(PYTHON) -m agent_baseline_lab.golden_flow \
		--profile community --baseline-cache "$(BASELINE_CACHE)"

golden-demo-mcp:
	$(PYTHON) -m agent_baseline_lab.golden_flow \
		--profile mcp --baseline-cache "$(BASELINE_CACHE)"

golden-demo-dry-run:
	$(PYTHON) -m agent_baseline_lab.golden_flow --profile community --dry-run

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

sandbox-create:
	sbx create --name abl-demo --deny-network exfiltration.invalid codex "$(CURDIR)/sample-app"

sandbox-run:
	sbx run codex --name abl-demo

sandbox-shell:
	sbx exec -it abl-demo bash

sandbox-rm:
	sbx rm abl-demo
