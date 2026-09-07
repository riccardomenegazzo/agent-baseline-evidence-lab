from __future__ import annotations

import re
from dataclasses import dataclass, asdict
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
    has_approval_guard: bool
    has_local_stdio_forbid: bool
    has_identity_url_binding: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def analyze_policy(path: str | Path) -> MCPPolicyAnalysis:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    normalized = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
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
        has_approval_guard="@requireApproval" in normalized,
        has_local_stdio_forbid=bool(
            re.search(r"forbid\s*\([^;]+resource\.type\s*==\s*\"local-stdio\"", normalized, re.DOTALL)
        ),
        has_identity_url_binding="resource.identityURL" in normalized,
    )
