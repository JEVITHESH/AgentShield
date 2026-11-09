"""Tests verifying AgentShield package foundation and public API."""

import pytest

import agentshield
from agentshield import (
    AgentShield,
    AutonomyLevel,
    ProtectionResult,
    SecurityDecision,
    __version__,
)


def test_package_version() -> None:
    """Verify package version is defined properly."""
    assert __version__ == "0.1.0"
    assert isinstance(agentshield.__version__, str)


def test_agentshield_initialization() -> None:
    """Verify default initialization of AgentShield engine."""
    shield = AgentShield()
    assert shield.config is not None
    assert "read_file" in shield.registered_tools
    assert "list_files" in shield.registered_tools


def test_tool_registration() -> None:
    """Verify tool registration and unregistration."""
    shield = AgentShield()
    custom_tool = "custom_compute_tool"
    assert custom_tool not in shield.registered_tools

    shield.register_tool(custom_tool)
    assert custom_tool in shield.registered_tools

    shield.unregister_tool(custom_tool)
    assert custom_tool not in shield.registered_tools


def test_protect_tool_registered_allowed() -> None:
    """Verify default registered tool allows execution."""
    shield = AgentShield()
    result = shield.protect_tool("read_file", {"path": "test.txt"})

    assert isinstance(result, ProtectionResult)
    assert result.allowed is True
    assert result.decision == SecurityDecision.ALLOW
    assert result.tool_name == "read_file"
    assert result.autonomy_level == AutonomyLevel.L4_AUTONOMOUS


def test_protect_tool_unregistered_blocked() -> None:
    """Verify unregistered tool is blocked by default."""
    shield = AgentShield()
    result = shield.protect_tool("unregistered_dangerous_tool", {"cmd": "rm -rf /"})

    assert isinstance(result, ProtectionResult)
    assert result.allowed is False
    assert result.decision == SecurityDecision.BLOCK
    assert result.autonomy_level == AutonomyLevel.L0_BLOCK
    assert result.risk_score == 1.0


def test_execute_protected_success() -> None:
    """Verify execute_protected runs target callable when allowed."""
    shield = AgentShield()

    def sample_func(msg: str) -> str:
        return f"Echo: {msg}"

    res = shield.execute_protected(
        tool_name="echo",
        target_func=sample_func,
        arguments={"msg": "hello"},
    )
    assert res == "Echo: hello"


def test_execute_protected_blocked_raises() -> None:
    """Verify execute_protected raises UnauthorizedToolError when blocked."""
    shield = AgentShield()

    def evil_func() -> str:
        return "hacked"

    with pytest.raises(agentshield.UnauthorizedToolError):
        shield.execute_protected(
            tool_name="unregistered_hack",
            target_func=evil_func,
            arguments={},
        )
