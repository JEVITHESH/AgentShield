"""Unit tests for AgentShield types, enums, and lattice models."""

from agentshield import (
    AutonomyLevel,
    ProtectionResult,
    SecurityDecision,
    SecurityLabel,
)


def test_security_lattice_ordering() -> None:
    """Verify security lattice levels: PUBLIC < INTERNAL < CONFIDENTIAL < CREDENTIAL."""
    assert SecurityLabel.PUBLIC < SecurityLabel.INTERNAL
    assert SecurityLabel.INTERNAL < SecurityLabel.CONFIDENTIAL
    assert SecurityLabel.CONFIDENTIAL < SecurityLabel.CREDENTIAL

    assert SecurityLabel.CREDENTIAL > SecurityLabel.PUBLIC
    assert SecurityLabel.CONFIDENTIAL >= SecurityLabel.INTERNAL
    assert SecurityLabel.PUBLIC <= SecurityLabel.PUBLIC


def test_information_flow_policy() -> None:
    """Verify can_flow_to respects lattice boundaries (no write down / declassification)."""
    # Public can flow to anything
    assert SecurityLabel.PUBLIC.can_flow_to(SecurityLabel.PUBLIC)
    assert SecurityLabel.PUBLIC.can_flow_to(SecurityLabel.INTERNAL)
    assert SecurityLabel.PUBLIC.can_flow_to(SecurityLabel.CONFIDENTIAL)
    assert SecurityLabel.PUBLIC.can_flow_to(SecurityLabel.CREDENTIAL)

    # Credential cannot flow to lower classifications
    assert not SecurityLabel.CREDENTIAL.can_flow_to(SecurityLabel.CONFIDENTIAL)
    assert not SecurityLabel.CREDENTIAL.can_flow_to(SecurityLabel.INTERNAL)
    assert not SecurityLabel.CREDENTIAL.can_flow_to(SecurityLabel.PUBLIC)


def test_autonomy_levels() -> None:
    """Verify autonomy levels monotonicity and labels."""
    assert AutonomyLevel.L0_BLOCK < AutonomyLevel.L1_APPROVAL
    assert AutonomyLevel.L1_APPROVAL < AutonomyLevel.L2_RESTRICTED
    assert AutonomyLevel.L2_RESTRICTED < AutonomyLevel.L3_MONITORED
    assert AutonomyLevel.L3_MONITORED < AutonomyLevel.L4_AUTONOMOUS

    assert AutonomyLevel.L0_BLOCK.label == "L0: Block"
    assert AutonomyLevel.L4_AUTONOMOUS.label == "L4: Autonomous"


def test_protection_result_model() -> None:
    """Verify ProtectionResult serialization and validation."""
    result = ProtectionResult(
        allowed=True,
        decision=SecurityDecision.ALLOW,
        autonomy_level=AutonomyLevel.L4_AUTONOMOUS,
        risk_score=0.15,
        trust_score=0.95,
        tool_name="list_files",
        reason="Safe read operation",
        metadata={"trace_id": "xyz"},
    )
    assert result.allowed is True
    assert result.risk_score == 0.15
    data = result.model_dump()
    assert data["decision"] == "allow"
    assert data["tool_name"] == "list_files"
