"""MCP middleware and protocol interception module for AgentShield."""

from agentshield.mcp.client import ShieldedMCPClient
from agentshield.mcp.interceptor import ToolInterceptor, ToolRequest, ToolSchema
from agentshield.mcp.middleware import MCPMiddleware

__all__ = [
    "MCPMiddleware",
    "ShieldedMCPClient",
    "ToolInterceptor",
    "ToolRequest",
    "ToolSchema",
]
