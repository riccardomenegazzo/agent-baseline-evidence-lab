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
    has_argument_guard: bool
    has_approval_guard: bool
    has_local_stdio_forbid: bool
    has_identity_url_binding: bool
    permitted_primordials: list[str]
    forbidden_primordials: list[str]
    has_authorize_primordial_forbid: bool
    has_dynamic_gateway_forbid: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _primordials_by_effect(normalized: str, effect: str) -> list[str]:
    names: set[str] = set()
    for match in re.finditer(rf"\b{effect}\s*\([^;]+;", normalized, re.DOTALL):
        statement = match.group(0)
        if 'MCP::Action::"invokePrimordial"' not in statement:
            continue
        names.update(re.findall(r'MCP::Primordial::"([^"]+)"', statement))
    return sorted(names)


def analyze_policy(path: str | Path) -> MCPPolicyAnalysis:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    normalized = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
    permitted_primordials = _primordials_by_effect(normalized, "permit")
    forbidden_primordials = _primordials_by_effect(normalized, "forbid")
    dynamic_gateway_names = {
        "mcp-add",
        "mcp-exec",
        "mcp-find",
        "mcp-config-set",
        "code-mode",
    }
    return MCPPolicyAnalysis(
        path=str(p),
        permit_statements=len(re.findall(r"\bpermit\s*\(", normalized)),
        forbid_statements=len(re.findall(r"\bforbid\s*\(", normalized)),
        has_actionless_permit=bool(
            re.search(r"permit\s*\(\s*principal\s*,\s*action\s*,\s*resource\s*\)\s*;", normalized)
        ),
        has_registration_scope='MCP::Action::"register"' in normalized,
        has_tool_scope='MCP::Action::"invokeTool"' in normalized,
        has_resource_scope='MCP::Action::"readResource"' in normalized,
        has_prompt_scope='MCP::Action::"getPrompt"' in normalized,
        has_primordial_scope='MCP::Action::"invokePrimordial"' in normalized,
        has_argument_guard=("context has args" in normalized and "context.args" in normalized),
        has_approval_guard="@requireApproval" in normalized,
        has_local_stdio_forbid=bool(
            re.search(r"forbid\s*\([^;]+resource\.type\s*==\s*\"local-stdio\"", normalized, re.DOTALL)
        ),
        has_identity_url_binding="resource.identityURL" in normalized,
        permitted_primordials=permitted_primordials,
        forbidden_primordials=forbidden_primordials,
        has_authorize_primordial_forbid=any(name.endswith("-authorize") for name in forbidden_primordials),
        has_dynamic_gateway_forbid=dynamic_gateway_names.issubset(set(forbidden_primordials)),
    )
