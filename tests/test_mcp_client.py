"""Unit tests for ShieldedMCPClient wrapper and proxy behavior."""

import pytest
from mcp.types import CallToolResult, TextContent

from agentshield import AgentShield, UnauthorizedToolError


class MockMCPSession:
    """Mock MCP ClientSession representing external session."""

    def __init__(self) -> None:
        self.initialized = True
        self.custom_property = "mcp-server-v1"

    async def call_tool(self, name: str, arguments: dict) -> CallToolResult:
        if name == "mock_echo":
            return CallToolResult(
                isError=False,
                content=[TextContent(type="text", text=f"Echo: {arguments.get('msg')}")],
            )
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=f"Unknown tool: {name}")],
        )

    def list_tools(self) -> list[str]:
        return ["mock_echo"]


@pytest.mark.asyncio
async def test_shielded_mcp_client_allowed_call() -> None:
    """Verify ShieldedMCPClient allows registered tool and delegates to session."""
    shield = AgentShield()
    shield.register_tool("mock_echo")

    mock_session = MockMCPSession()
    client = shield.wrap_mcp_client(mock_session)

    res = await client.call_tool("mock_echo", {"msg": "hello world"})
    assert isinstance(res, CallToolResult)
    assert res.isError is False
    assert res.content[0].text == "Echo: hello world"


@pytest.mark.asyncio
async def test_shielded_mcp_client_blocked_call() -> None:
    """Verify ShieldedMCPClient blocks unregistered tool before reaching session."""
    shield = AgentShield()
    mock_session = MockMCPSession()
    client = shield.wrap_mcp_client(mock_session)

    with pytest.raises(UnauthorizedToolError):
        await client.call_tool("unregistered_tool", {})


def test_shielded_mcp_client_delegation() -> None:
    """Verify attributes not defined on proxy delegate to underlying session."""
    shield = AgentShield()
    mock_session = MockMCPSession()
    client = shield.wrap_mcp_client(mock_session)

    assert client.initialized is True
    assert client.custom_property == "mcp-server-v1"
    assert client.list_tools() == ["mock_echo"]
