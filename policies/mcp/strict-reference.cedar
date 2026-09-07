// Reference policy for the lab. It is intentionally scoped and default-deny.
// Replace the demo identity URL and server name before using it in a real organization.

permit (principal, action == MCP::Action::"register", resource)
when {
  resource in MCP::Server::"example" &&
  resource.identityURL == "https://mcp.example.com/mcp"
};

permit (principal, action == MCP::Action::"invokeTool", resource)
when {
  resource in MCP::Server::"example" &&
  resource.readOnly == true
};

@requireApproval("non-read-only tool call")
permit (principal, action == MCP::Action::"invokeTool", resource)
when {
  resource in MCP::Server::"example" &&
  resource.readOnly == false
};

permit (principal, action == MCP::Action::"readResource", resource)
when { resource in MCP::Server::"example" };

permit (principal, action == MCP::Action::"getPrompt", resource)
when { resource in MCP::Server::"example" };

forbid (principal, action == MCP::Action::"register", resource)
when { resource.type == "local-stdio" };

// Prevent dynamic gateway expansion in this strict reference posture.
forbid (principal, action == MCP::Action::"invokePrimordial", resource)
when { resource in MCP::Primordial::"mcp-add" };

forbid (principal, action == MCP::Action::"invokePrimordial", resource)
when { resource in MCP::Primordial::"code-mode" };
