from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class MCPPolicyAnalysis:
    path: str
    permit_statements: int
    forbid_statements: int
    has_actionless_permit: bool
    has_registration_scope: bool
    has_tool_scope: bool
    has_resource_scope: bool
    has_prompt_scope: bool
    has_primordial_scope: bool
    has_primordial_permit: bool
    has_primordial_forbid: bool
    forbidden_primordial_resources: list[str]
    has_argument_guard: bool
    has_approval_guard: bool
    has_local_stdio_forbid: bool
    has_identity_url_binding: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _statements(normalized: str, kind: str) -> list[str]:
    return re.findall(rf"\b{kind}\s*\([^;]+;", normalized, flags=re.DOTALL)


def analyze_policy(path: str | Path) -> MCPPolicyAnalysis:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    normalized = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
    permits = _statements(normalized, "permit")
    forbids = _statements(normalized, "forbid")
    primordial_permits = [statement for statement in permits if 'MCP::Action::"invokePrimordial"' in statement]
    primordial_forbids = [statement for statement in forbids if 'MCP::Action::"invokePrimordial"' in statement]
    forbidden_resources = sorted(
        {
            match
            for statement in primordial_forbids
            for match in re.findall(r'MCP::Primordial::"([^"]+)"', statement)
        }
    )
    return MCPPolicyAnalysis(
        path=str(p),
        permit_statements=len(permits),
        forbid_statements=len(forbids),
        has_actionless_permit=bool(
            re.search(r"permit\s*\(\s*principal\s*,\s*action\s*,\s*resource\s*\)\s*;", normalized)
        ),
        has_registration_scope='MCP::Action::"register"' in normalized,
        has_tool_scope='MCP::Action::"invokeTool"' in normalized,
        has_resource_scope='MCP::Action::"readResource"' in normalized,
        has_prompt_scope='MCP::Action::"getPrompt"' in normalized,
        has_primordial_scope='MCP::Action::"invokePrimordial"' in normalized,
        has_primordial_permit=bool(primordial_permits),
        has_primordial_forbid=bool(primordial_forbids),
        forbidden_primordial_resources=forbidden_resources,
        has_argument_guard=("context has args" in normalized and "context.args" in normalized),
        has_approval_guard="@requireApproval" in normalized,
        has_local_stdio_forbid=bool(
            re.search(r"forbid\s*\([^;]+resource\.type\s*==\s*\"local-stdio\"", normalized, re.DOTALL)
        ),
        has_identity_url_binding="resource.identityURL" in normalized,
    )
