"""Shielded MCP Client wrapper providing transparent security proxying."""

import inspect
from typing import Any, Dict, Optional

from mcp.types import CallToolResult

from agentshield.mcp.middleware import MCPMiddleware


class ShieldedMCPClient:
    """Transparent proxy wrapping an MCP ClientSession or tool executor with AgentShield."""

    def __init__(
        self,
        target_session: Any,
        middleware: Optional[MCPMiddleware] = None,
        agent_id: str = "default_agent",
        session_id: str = "default_session",
    ) -> None:
        """Initialize ShieldedMCPClient.

        Parameters
        ----------
        target_session : Any
            The underlying MCP ClientSession, mock client, or object implementing call_tool.
        middleware : Optional[MCPMiddleware]
            The MCPMiddleware instance enforcing security policies.
        agent_id : str
            Identifier for the autonomous agent.
        session_id : str
            Active session context ID.
        """
        self._target_session = target_session
        self.middleware = middleware or MCPMiddleware()
        self.agent_id = agent_id
        self.session_id = session_id

    async def call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> CallToolResult:
        """Asynchronously intercept, validate, and execute an MCP tool through target session."""
        args = arguments or {}

        async def _forwarder(**kwargs: Any) -> Any:
            # Delegate downstream call to the wrapped session
            session_call = getattr(self._target_session, "call_tool", None)
            if session_call is None:
                raise AttributeError(
                    f"Wrapped session {type(self._target_session).__name__} does not have 'call_tool'"
                )
            if inspect.iscoroutinefunction(session_call):
                return await session_call(name, kwargs)
            return session_call(name, kwargs)

        return await self.middleware.aintercept_call_tool(
            name=name,
            arguments=args,
            handler=_forwarder,
            agent_id=self.agent_id,
            session_id=self.session_id,
        )

    def call_tool_sync(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> CallToolResult:
        """Synchronously intercept, validate, and execute tool call."""
        args = arguments or {}

        def _forwarder(**kwargs: Any) -> Any:
            session_call = getattr(self._target_session, "call_tool", None)
            if session_call is None:
                raise AttributeError(
                    f"Wrapped session {type(self._target_session).__name__} does not have 'call_tool'"
                )
            if inspect.iscoroutinefunction(session_call):
                raise TypeError("Wrapped session call_tool is async; use call_tool() instead")
            return session_call(name, kwargs)

        return self.middleware.intercept_call_tool(
            name=name,
            arguments=args,
            handler=_forwarder,
            agent_id=self.agent_id,
            session_id=self.session_id,
        )

    def __getattr__(self, name: str) -> Any:
        """Transparently delegate all other calls and attributes to the underlying session."""
        return getattr(self._target_session, name)
