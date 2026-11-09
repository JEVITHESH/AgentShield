"""Strongly-typed exception hierarchy for AgentShield SDK.

All exceptions raised by the SDK inherit from `AgentShieldError`.
"""

from typing import Any, Dict, Optional


class AgentShieldError(Exception):
    """Base exception for all AgentShield errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


class ConfigurationError(AgentShieldError):
    """Raised when configuration validation or initialization fails."""
    pass


class SecurityViolationError(AgentShieldError):
    """Base exception raised when an operation violates security policy."""
    pass


class UnauthorizedToolError(SecurityViolationError):
    """Raised when an unregistered or prohibited tool is invoked."""
    pass


class DataLeakageError(SecurityViolationError):
    """Raised when an information flow violates security lattice policies (sink clearance)."""
    pass


class PromptInjectionDetectedError(SecurityViolationError):
    """Raised when high-confidence prompt injection indicators are detected."""
    pass


class CumulativeRiskExceededError(SecurityViolationError):
    """Raised when session cumulative tool-chain risk exceeds safety thresholds."""
    pass


class IntegrityCheckFailedError(SecurityViolationError):
    """Raised when pre-execution integrity checks fail or parameter digests mismatch."""
    pass


class ApprovalRejectedError(SecurityViolationError):
    """Raised when a human approver explicitly rejects a sensitive operation."""
    pass


class ApprovalRequiredException(AgentShieldError):
    """Signal indicating that an operation requires human approval before proceeding."""

    def __init__(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        risk_score: float,
        approval_id: str,
        reason: str = "Operation requires human approval",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        extended_details = {
            "tool_name": tool_name,
            "arguments": arguments,
            "risk_score": risk_score,
            "approval_id": approval_id,
            **(details or {}),
        }
        super().__init__(f"{reason} (Tool: {tool_name}, Approval ID: {approval_id})", extended_details)
        self.tool_name = tool_name
        self.arguments = arguments
        self.risk_score = risk_score
        self.approval_id = approval_id


class ApprovalTimeoutError(AgentShieldError):
    """Raised when a pending human approval request expires."""
    pass


class AuditLoggingError(AgentShieldError):
    """Raised when audit record persistence or verification fails."""
    pass


class ToolExecutionError(AgentShieldError):
    """Raised when downstream tool execution fails."""
    pass


# Convenience alias matching standard error suffix conventions
ApprovalRequiredError = ApprovalRequiredException

