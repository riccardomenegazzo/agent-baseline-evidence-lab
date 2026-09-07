from __future__ import annotations

from .models import Control

# IDs and short titles mirror the public Agent Baseline v1.0-draft index.
# The authoritative requirements remain upstream; see baseline/source.json.
_CONTROL_ROWS = [
    ("DIS-01", "DIS", "Authoritative agent registry", "Record"),
    ("DIS-02", "DIS", "Ownership and risk context", "Record"),
    ("DIS-03", "DIS", "Status and decision history", "Record"),
    ("DIS-04", "DIS", "Authoritative component registry", "Record"),
    ("DIS-05", "DIS", "Agent composition mapping", "Record"),
    ("DIS-06", "DIS", "Effective-access mapping", "Record"),
    ("DIS-07", "DIS", "Automated discovery and reconciliation", "Detection"),
    ("CON-01", "CON", "Admission enforcement", "Enforcement"),
    ("CON-02", "CON", "Toxic capability combinations", "Enforcement"),
    ("CON-03", "CON", "Isolated and confined execution", "Enforcement"),
    ("CON-04", "CON", "Use-case-scoped capability profiles", "Enforcement"),
    ("AUT-01", "AUT", "Distinct identity and action attribution", "Evidence"),
    ("AUT-02", "AUT", "Purpose and task-bound authority", "Decision"),
    ("AUT-03", "AUT", "Delegation attenuation", "Enforcement"),
    ("AUT-04", "AUT", "Just-in-time credentialing", "Enforcement"),
    ("AUT-05", "AUT", "Independent approval", "Decision"),
    ("AUT-06", "AUT", "Fail-closed authorization and circuit breaking", "Enforcement"),
    ("AUT-07", "AUT", "Step-up verification", "Decision"),
    ("AUT-08", "AUT", "Just-in-time authority elevation", "Decision"),
    ("AUT-09", "AUT", "Proof-of-possession credential binding", "Enforcement"),
    ("OBS-01", "OBS", "Agent-native telemetry", "Evidence"),
    ("OBS-02", "OBS", "End-to-end correlation", "Evidence"),
    ("OBS-03", "OBS", "Behaviour and drift monitoring", "Detection"),
    ("OBS-04", "OBS", "Unintended action detection", "Detection"),
    ("OBS-05", "OBS", "Intent-to-outcome evidence", "Evidence"),
    ("OBS-06", "OBS", "Evidence integrity, completeness and protection", "Evidence"),
    ("VAL-01", "VAL", "Agent-specific security testing", "Assurance"),
    ("VAL-02", "VAL", "First-party agentic components testing", "Assurance"),
    ("VAL-03", "VAL", "Agent-generated artifact testing", "Assurance"),
    ("VAL-04", "VAL", "Agent outcome validation", "Assurance"),
    ("RES-01", "RES", "Immediate stop and authority revocation", "Response"),
    ("RES-02", "RES", "Version and component quarantine", "Response"),
    ("RES-03", "RES", "Impact scoping and evidence preservation", "Response"),
    ("RES-04", "RES", "Safe failure and non-agent fallback", "Response"),
    ("RES-05", "RES", "Agentic component rug-pull protection", "Response"),
]

CONTROLS = [Control(*row) for row in _CONTROL_ROWS]
CONTROL_BY_ID = {c.id: c for c in CONTROLS}
OUTCOME_NAMES = {
    "DIS": "Discover",
    "CON": "Constrain",
    "AUT": "Authorize",
    "OBS": "Observe",
    "VAL": "Validate",
    "RES": "Respond",
}
