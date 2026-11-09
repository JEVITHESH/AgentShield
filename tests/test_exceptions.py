"""Unit tests for AgentShield exception hierarchy."""

from agentshield import (
    AgentShieldError,
    ApprovalRejectedError,
    ApprovalRequiredException,
    ApprovalTimeoutError,
    AuditLoggingError,
    ConfigurationError,
    CumulativeRiskExceededError,
    DataLeakageError,
    IntegrityCheckFailedError,
    PromptInjectionDetectedError,
    SecurityViolationError,
    ToolExecutionError,
    UnauthorizedToolError,
)


def test_exception_hierarchy() -> None:
    """Verify that all custom exceptions inherit from AgentShieldError."""
    assert issubclass(SecurityViolationError, AgentShieldError)
    assert issubclass(ConfigurationError, AgentShieldError)
    assert issubclass(UnauthorizedToolError, SecurityViolationError)
    assert issubclass(DataLeakageError, SecurityViolationError)
    assert issubclass(PromptInjectionDetectedError, SecurityViolationError)
    assert issubclass(CumulativeRiskExceededError, SecurityViolationError)
    assert issubclass(IntegrityCheckFailedError, SecurityViolationError)
    assert issubclass(ApprovalRejectedError, SecurityViolationError)
    assert issubclass(ApprovalRequiredException, AgentShieldError)
    assert issubclass(ApprovalTimeoutError, AgentShieldError)
    assert issubclass(AuditLoggingError, AgentShieldError)
    assert issubclass(ToolExecutionError, AgentShieldError)


def test_exception_details_formatting() -> None:
    """Verify exception message and details formatting."""
    exc = SecurityViolationError("Denied", details={"rule": "no-read-up", "level": 2})
    assert "Denied" in str(exc)
    assert "no-read-up" in str(exc)
    assert exc.details["level"] == 2


def test_approval_required_exception() -> None:
    """Verify ApprovalRequiredException attributes."""
    exc = ApprovalRequiredException(
        tool_name="delete_database",
        arguments={"db": "prod"},
        risk_score=0.92,
        approval_id="app-12345",
        reason="Destructive command detected",
    )
    assert exc.tool_name == "delete_database"
    assert exc.arguments == {"db": "prod"}
    assert exc.risk_score == 0.92
    assert exc.approval_id == "app-12345"
    assert "app-12345" in str(exc)
