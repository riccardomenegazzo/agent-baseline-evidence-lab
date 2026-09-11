// Read-only Docker Hardened Images MCP posture for the full live demo.
// Docker MCP governance is default-deny when policy enforcement is active.

permit (principal, action == MCP::Action::"register", resource)
when {
  resource in MCP::Server::"dhi" &&
  resource.identityURL == "https://dhi.io/mcp"
};

permit (principal, action == MCP::Action::"invokeTool", resource)
when {
  resource in MCP::Server::"dhi" &&
  resource.readOnly == true
};

// The lab never needs mirror-management or other non-read-only DHI operations.
forbid (principal, action == MCP::Action::"invokeTool", resource)
when {
  resource in MCP::Server::"dhi" &&
  resource.readOnly == false
};

permit (principal, action == MCP::Action::"readResource", resource)
when { resource in MCP::Server::"dhi" };

permit (principal, action == MCP::Action::"getPrompt", resource)
when { resource in MCP::Server::"dhi" };

// Host-run local stdio MCP servers sit outside the sandbox VM boundary.
forbid (principal, action == MCP::Action::"register", resource)
when { resource.type == "local-stdio" };

// Keep the demo gateway static: no runtime server attachment or code-mode expansion.
forbid (principal, action == MCP::Action::"invokePrimordial", resource)
when { resource in MCP::Primordial::"mcp-add" };

forbid (principal, action == MCP::Action::"invokePrimordial", resource)
when { resource in MCP::Primordial::"code-mode" };
