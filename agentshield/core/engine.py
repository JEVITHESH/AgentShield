"""Main AgentShield facade and engine coordinator."""

import uuid
from typing import Any, Callable, Dict, List, Optional

from agentshield.core.config import ShieldConfig
from agentshield.core.exceptions import ConfigurationError, UnauthorizedToolError
from agentshield.core.types import (
    AutonomyLevel,
    ProtectionResult,
    SecurityDecision,
)
from agentshield.mcp.client import ShieldedMCPClient
from agentshield.mcp.interceptor import ToolRequest, ToolSchema
from agentshield.mcp.middleware import MCPMiddleware
from agentshield.risk.engine import RiskEngine


class AgentShield:
    """AgentShield: Dynamic security and autonomy-control middleware for MCP AI agents.

    Provides high-level APIs to protect tool execution, inspect risks, maintain
    Bayesian trust, enforce information flow policies, and log audit trails.
    """

    def __init__(self, config: Optional[ShieldConfig] = None) -> None:
        """Initialize AgentShield with configuration."""
        self.config = config or ShieldConfig()
        if not isinstance(self.config, ShieldConfig):
            raise ConfigurationError("Invalid configuration: must be an instance of ShieldConfig")

        # In-memory registry of tools permitted for execution
        self._registered_tools = set(self.config.registered_tools)

        # MCP Middleware integration
        self.mcp_middleware = MCPMiddleware(shield=self)

        # Dynamic 8-factor Risk Assessment Engine
        self.risk_engine = RiskEngine(
            weights=self.config.risk_weights,
            thresholds=self.config.thresholds,
        )

        # Hook placeholders for Phase 5-10 modules
        self._trust_engine = None
        self._decision_core = None
        self._approval_manager = None
        self._audit_logger = None

    @property
    def registered_tools(self) -> set[str]:
        """Return a copy of registered tools."""
        return set(self._registered_tools)

    def register_tool(
        self,
        tool_name: str,
        schema: Optional[ToolSchema] = None,
        handler: Optional[Callable[..., Any]] = None,
    ) -> None:
        """Register a permitted tool name with optional schema and execution handler."""
        if not tool_name or not isinstance(tool_name, str):
            raise ConfigurationError("Tool name must be a non-empty string")
        clean_name = tool_name.strip()
        self._registered_tools.add(clean_name)

        if schema:
            self.mcp_middleware.register_tool_schema(schema)
        if handler:
            self.mcp_middleware.register_tool_handler(clean_name, handler, schema=schema)

    def unregister_tool(self, tool_name: str) -> None:
        """Remove a tool from the permitted tool registry."""
        self._registered_tools.discard(tool_name.strip())

    def wrap_mcp_client(
        self,
        session: Any,
        agent_id: str = "default_agent",
        session_id: str = "default_session",
    ) -> ShieldedMCPClient:
        """Wrap an MCP ClientSession in a ShieldedMCPClient proxy."""
        return ShieldedMCPClient(
            target_session=session,
            middleware=self.mcp_middleware,
            agent_id=agent_id,
            session_id=session_id,
        )

    def protect_tool(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        agent_id: str = "default_agent",
        session_id: str = "default_session",
        user_intent: Optional[str] = None,
        raw_prompt: Optional[str] = None,
        session_history: Optional[List[Dict[str, Any]]] = None,
        session_violations: int = 0,
        session_total: int = 0,
        previous_tools: Optional[List[str]] = None,
    ) -> ProtectionResult:
        """Assess and protect an MCP tool request before execution.

        Parameters
        ----------
        tool_name : str
            The name of the MCP tool to be executed.
        arguments : Optional[Dict[str, Any]]
            Dictionary of tool parameters.
        agent_id : str
            Identifier for the autonomous agent making the request.
        session_id : str
            Active session identifier for cumulative context tracking.
        user_intent : Optional[str]
            User intent or goal description for intent risk assessment.
        raw_prompt : Optional[str]
            Raw user prompt for injection scanning.
        session_history : Optional[List[Dict[str, Any]]]
            Recent operation history for behavioral anomaly evaluation.
        session_violations : int
            Prior security violation count in session.
        session_total : int
            Total operations performed in session.
        previous_tools : Optional[List[str]]
            List of tool names previously executed in current chain.

        Returns
        -------
        ProtectionResult
            Detailed assessment containing whether the tool is allowed,
            the calculated risk score, autonomy level, and decision.
        """
        args = arguments or {}

        # 1. Default-deny check for unregistered tools
        if self.config.default_deny and tool_name not in self._registered_tools:
            return ProtectionResult(
                allowed=False,
                decision=SecurityDecision.BLOCK,
                autonomy_level=AutonomyLevel.L0_BLOCK,
                risk_score=1.0,
                trust_score=0.0,
                tool_name=tool_name,
                reason=f"Tool '{tool_name}' is not registered and default_deny is enabled",
                metadata={"agent_id": agent_id, "session_id": session_id, "args": args},
            )

        # 2. Retrieve tool metadata and schema
        schema = self.mcp_middleware.get_tool_schema(tool_name)

        # 3. Dynamic 8-factor Risk Assessment
        req = ToolRequest(
            tool_name=tool_name,
            arguments=args,
            agent_id=agent_id,
            session_id=session_id,
        )
        assessment = self.risk_engine.assess(
            request=req,
            schema=schema,
            user_intent=user_intent,
            raw_prompt=raw_prompt,
            session_history=session_history,
            session_violations=session_violations,
            session_total=session_total,
            previous_tools=previous_tools,
        )

        overall_score = assessment.overall_score
        thresh = self.config.thresholds

        # 4. Map risk score to autonomy level and decision
        if overall_score >= thresh.block_threshold:
            decision = SecurityDecision.BLOCK
            autonomy_level = AutonomyLevel.L0_BLOCK
            allowed = False
            approval_id = None
        elif overall_score >= thresh.approval_threshold:
            decision = SecurityDecision.REQUIRE_APPROVAL
            autonomy_level = AutonomyLevel.L1_APPROVAL
            allowed = False
            approval_id = f"app-{uuid.uuid4().hex[:8]}"
        elif overall_score >= thresh.restricted_threshold:
            decision = SecurityDecision.MONITOR
            autonomy_level = AutonomyLevel.L2_RESTRICTED
            allowed = True
            approval_id = None
        elif overall_score >= thresh.monitored_threshold:
            decision = SecurityDecision.MONITOR
            autonomy_level = AutonomyLevel.L3_MONITORED
            allowed = True
            approval_id = None
        else:
            decision = SecurityDecision.ALLOW
            autonomy_level = AutonomyLevel.L4_AUTONOMOUS
            allowed = True
            approval_id = None

        return ProtectionResult(
            allowed=allowed,
            decision=decision,
            autonomy_level=autonomy_level,
            risk_score=overall_score,
            trust_score=0.9,  # Baseline trust; dynamic Bayesian trust added in Phase 5
            tool_name=tool_name,
            reason=assessment.summary,
            approval_id=approval_id,
            metadata={
                "agent_id": agent_id,
                "session_id": session_id,
                "args": args,
                "risk_assessment": assessment.model_dump(),
            },
        )

    def execute_protected(
        self,
        tool_name: str,
        target_func: Callable[..., Any],
        arguments: Optional[Dict[str, Any]] = None,
        agent_id: str = "default_agent",
        session_id: str = "default_session",
    ) -> Any:
        """Inspect and conditionally execute a callable tool target."""
        args = arguments or {}
        result = self.protect_tool(
            tool_name=tool_name,
            arguments=args,
            agent_id=agent_id,
            session_id=session_id,
        )

        if not result.allowed:
            raise UnauthorizedToolError(
                f"Execution blocked for tool '{tool_name}': {result.reason}",
                details={"result": result.model_dump()},
            )

        return target_func(**args)
