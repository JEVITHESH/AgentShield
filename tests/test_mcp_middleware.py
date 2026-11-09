"""Unit tests for MCPMiddleware tool interception and request execution."""

import pytest
from mcp.types import CallToolRequest, CallToolRequestParams, CallToolResult

from agentshield import AgentShield, ShieldConfig, UnauthorizedToolError
from agentshield.mcp.middleware import MCPMiddleware


def test_middleware_sync_execution() -> None:
    """Verify synchronous tool call interception and execution."""
    shield = AgentShield()
    middleware = shield.mcp_middleware

    def add_tool(a: int, b: int) -> int:
        return a + b

    middleware.register_tool_handler("add", add_tool)
    result = middleware.intercept_call_tool("add", {"a": 5, "b": 7})

    assert isinstance(result, CallToolResult)
    assert result.isError is False
    assert len(result.content) == 1
    assert result.content[0].text == "12"


@pytest.mark.asyncio
async def test_middleware_async_execution() -> None:
    """Verify asynchronous tool call interception and execution."""
    shield = AgentShield()
    middleware = shield.mcp_middleware

    async def fetch_data(key: str) -> str:
        return f"value_for_{key}"

    middleware.register_tool_handler("fetch_data", fetch_data)
    result = await middleware.aintercept_call_tool("fetch_data", {"key": "token"})

    assert result.isError is False
    assert result.content[0].text == "value_for_token"


def test_middleware_blocked_raises_error() -> None:
    """Verify middleware raises UnauthorizedToolError on unregistered tool."""
    shield = AgentShield(config=ShieldConfig(default_deny=True))
    middleware = shield.mcp_middleware

    with pytest.raises(UnauthorizedToolError):
        middleware.intercept_call_tool("unregistered_tool", {})


def test_middleware_blocked_returns_error_result() -> None:
    """Verify middleware returns error CallToolResult when raise_on_block is False."""
    shield = AgentShield(config=ShieldConfig(default_deny=True))
    middleware = MCPMiddleware(shield=shield, raise_on_block=False)

    result = middleware.intercept_call_tool("unregistered_tool", {})
    assert result.isError is True
    assert "Blocked by AgentShield" in result.content[0].text


def test_handle_mcp_native_request() -> None:
    """Verify handling of native MCP CallToolRequest object."""
    shield = AgentShield()
    middleware = shield.mcp_middleware
    middleware.register_tool_handler("greet", lambda name: f"Hello, {name}!")

    mcp_req = CallToolRequest(
        method="tools/call",
        params=CallToolRequestParams(name="greet", arguments={"name": "Alice"}),
    )

    result = middleware.handle_mcp_request(mcp_req)
    assert result.isError is False
    assert result.content[0].text == "Hello, Alice!"
