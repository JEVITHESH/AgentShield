"""MCP Middleware for intercepting, validating, and policy-controlling tool calls."""

import inspect
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Optional, Union

from mcp.types import CallToolRequest, CallToolResult, TextContent

from agentshield.core.exceptions import (
    ApprovalRequiredException,
    SecurityViolationError,
    UnauthorizedToolError,
)
from agentshield.core.types import ProtectionResult, SecurityDecision
from agentshield.mcp.interceptor import ToolInterceptor, ToolRequest, ToolSchema

if TYPE_CHECKING:
    from agentshield.core.engine import AgentShield


class MCPMiddleware:
    """Middleware between MCP Client/Server to enforce security boundaries."""

    def __init__(
        self,
        shield: Optional["AgentShield"] = None,
        raise_on_block: bool = True,
    ) -> None:
        """Initialize MCPMiddleware.

        Parameters
        ----------
        shield : Optional[AgentShield]
            Parent AgentShield engine instance.
        raise_on_block : bool
            If True, raises SecurityViolationError on blocked calls.
            If False, returns CallToolResult with isError=True and explanation.
        """
        self._shield = shield
        self.raise_on_block = raise_on_block
        self.interceptor = ToolInterceptor()
        self._schemas: Dict[str, ToolSchema] = {}
        self._tool_handlers: Dict[str, Callable[..., Any]] = {}

    def set_shield(self, shield: "AgentShield") -> None:
        """Bind or update parent AgentShield engine."""
        self._shield = shield

    def register_tool_schema(self, schema: ToolSchema) -> None:
        """Register a tool definition with schema, tier, and security label."""
        self._schemas[schema.name] = schema
        if self._shield:
            self._shield.register_tool(schema.name)

    def get_tool_schema(self, tool_name: str) -> Optional[ToolSchema]:
        """Retrieve schema for a registered tool."""
        return self._schemas.get(tool_name)

    def register_tool_handler(
        self,
        name: str,
        handler: Callable[..., Any],
        schema: Optional[ToolSchema] = None,
    ) -> None:
        """Register an execution handler callable for a named tool."""
        self._tool_handlers[name] = handler
        if schema:
            self.register_tool_schema(schema)
        elif name not in self._schemas:
            # Register default schema
            self.register_tool_schema(ToolSchema(name=name))

    def evaluate_policy(self, request: ToolRequest) -> ProtectionResult:
        """Evaluate AgentShield security policy for the given tool request."""
        if self._shield:
            return self._shield.protect_tool(
                tool_name=request.tool_name,
                arguments=request.arguments,
                agent_id=request.agent_id,
                session_id=request.session_id,
            )

        # Standalone default policy if no shield bound
        return ProtectionResult(
            allowed=True,
            decision=SecurityDecision.ALLOW,
            autonomy_level=4,  # L4_AUTONOMOUS
            risk_score=0.1,
            trust_score=0.9,
            tool_name=request.tool_name,
            reason="Allowed by standalone MCP middleware policy",
        )

    def _format_error_result(self, message: str) -> CallToolResult:
        """Create a standard MCP CallToolResult indicating an error."""
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=message)],
        )

    def _format_success_result(self, raw_output: Any) -> CallToolResult:
        """Convert arbitrary tool execution output to standard CallToolResult."""
        if isinstance(raw_output, CallToolResult):
            return raw_output

        text = raw_output if isinstance(raw_output, str) else str(raw_output)
        return CallToolResult(
            isError=False,
            content=[TextContent(type="text", text=text)],
        )

    def intercept_call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
        agent_id: str = "default_agent",
        session_id: str = "default_session",
    ) -> CallToolResult:
        """Synchronously intercept, validate, and execute an MCP tool call."""
        raw_request = ToolRequest(
            tool_name=name,
            arguments=arguments or {},
            agent_id=agent_id,
            session_id=session_id,
        )
        schema = self.get_tool_schema(name)

        try:
            req = self.interceptor.intercept_pre(raw_request, schema)
        except Exception as exc:
            self.interceptor.intercept_error(raw_request, exc)
            if self.raise_on_block:
                raise
            return self._format_error_result(f"Pre-execution validation failed: {exc}")

        # Policy evaluation
        decision = self.evaluate_policy(req)
        if not decision.allowed:
            err = UnauthorizedToolError(
                f"Tool '{name}' blocked: {decision.reason}",
                details={"decision": decision.model_dump()},
            )
            self.interceptor.intercept_error(req, err)
            if self.raise_on_block:
                raise err
            return self._format_error_result(f"Blocked by AgentShield: {decision.reason}")

        # Check approval requirement
        if decision.decision == SecurityDecision.REQUIRE_APPROVAL:
            approval_exc = ApprovalRequiredException(
                tool_name=name,
                arguments=req.arguments,
                risk_score=decision.risk_score,
                approval_id=decision.approval_id or "pending",
                reason=decision.reason,
            )
            self.interceptor.intercept_error(req, approval_exc)
            if self.raise_on_block:
                raise approval_exc
            return self._format_error_result(
                f"Approval required for tool '{name}' (ID: {decision.approval_id})"
            )

        # Resolve handler
        target_handler = handler or self._tool_handlers.get(name)
        if target_handler is None:
            err = UnauthorizedToolError(f"No execution handler registered for tool '{name}'")
            self.interceptor.intercept_error(req, err)
            if self.raise_on_block:
                raise err
            return self._format_error_result(str(err))

        try:
            if inspect.iscoroutinefunction(target_handler):
                raise TypeError(
                    f"Tool handler for '{name}' is asynchronous. "
                    "Use aintercept_call_tool() instead."
                )
            raw_result = target_handler(**req.arguments)
            final_result = self.interceptor.intercept_post(req, raw_result)
            return self._format_success_result(final_result)
        except Exception as exc:
            self.interceptor.intercept_error(req, exc)
            if self.raise_on_block and isinstance(exc, SecurityViolationError):
                raise
            return self._format_error_result(f"Execution error in tool '{name}': {exc}")

    async def aintercept_call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
        handler: Optional[Union[Callable[..., Any], Callable[..., Awaitable[Any]]]] = None,
        agent_id: str = "default_agent",
        session_id: str = "default_session",
    ) -> CallToolResult:
        """Asynchronously intercept, validate, and execute an MCP tool call."""
        raw_request = ToolRequest(
            tool_name=name,
            arguments=arguments or {},
            agent_id=agent_id,
            session_id=session_id,
        )
        schema = self.get_tool_schema(name)

        try:
            req = self.interceptor.intercept_pre(raw_request, schema)
        except Exception as exc:
            self.interceptor.intercept_error(raw_request, exc)
            if self.raise_on_block:
                raise
            return self._format_error_result(f"Pre-execution validation failed: {exc}")

        # Policy evaluation
        decision = self.evaluate_policy(req)
        if not decision.allowed:
            err = UnauthorizedToolError(
                f"Tool '{name}' blocked: {decision.reason}",
                details={"decision": decision.model_dump()},
            )
            self.interceptor.intercept_error(req, err)
            if self.raise_on_block:
                raise err
            return self._format_error_result(f"Blocked by AgentShield: {decision.reason}")

        if decision.decision == SecurityDecision.REQUIRE_APPROVAL:
            approval_exc = ApprovalRequiredException(
                tool_name=name,
                arguments=req.arguments,
                risk_score=decision.risk_score,
                approval_id=decision.approval_id or "pending",
                reason=decision.reason,
            )
            self.interceptor.intercept_error(req, approval_exc)
            if self.raise_on_block:
                raise approval_exc
            return self._format_error_result(
                f"Approval required for tool '{name}' (ID: {decision.approval_id})"
            )

        target_handler = handler or self._tool_handlers.get(name)
        if target_handler is None:
            err = UnauthorizedToolError(f"No execution handler registered for tool '{name}'")
            self.interceptor.intercept_error(req, err)
            if self.raise_on_block:
                raise err
            return self._format_error_result(str(err))

        try:
            if inspect.iscoroutinefunction(target_handler):
                raw_result = await target_handler(**req.arguments)
            else:
                raw_result = target_handler(**req.arguments)

            final_result = self.interceptor.intercept_post(req, raw_result)
            return self._format_success_result(final_result)
        except Exception as exc:
            self.interceptor.intercept_error(req, exc)
            if self.raise_on_block and isinstance(exc, SecurityViolationError):
                raise
            return self._format_error_result(f"Execution error in tool '{name}': {exc}")

    def handle_mcp_request(self, request: CallToolRequest) -> CallToolResult:
        """Handle incoming native MCP CallToolRequest synchronously."""
        return self.intercept_call_tool(
            name=request.params.name,
            arguments=request.params.arguments,
        )

    async def ahandle_mcp_request(self, request: CallToolRequest) -> CallToolResult:
        """Handle incoming native MCP CallToolRequest asynchronously."""
        return await self.aintercept_call_tool(
            name=request.params.name,
            arguments=request.params.arguments,
        )
