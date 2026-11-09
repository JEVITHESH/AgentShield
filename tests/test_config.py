"""Unit tests for AgentShield configuration models."""

import pytest
from pydantic import ValidationError

from agentshield import (
    RiskThresholdsConfig,
    RiskWeightsConfig,
    ShieldConfig,
)


def test_default_config_valid() -> None:
    """Verify default ShieldConfig initializes with valid subconfigs."""
    config = ShieldConfig()
    assert config.enabled is True
    assert config.default_deny is True
    assert len(config.registered_tools) > 0
    assert config.risk_weights is not None
    assert config.thresholds is not None
    assert config.trust is not None


def test_risk_weights_normalization() -> None:
    """Verify weights normalization sums to 1.0."""
    weights = RiskWeightsConfig(
        tool_criticality=2.0,
        data_sensitivity=2.0,
        user_intent=2.0,
        prompt_injection=2.0,
        behavioral=2.0,
        historical=2.0,
        chain_dependency=2.0,
        operation_risk=2.0,
    )
    normalized = weights.normalized()
    total = sum(normalized.values())
    assert pytest.approx(total, 1e-6) == 1.0
    for v in normalized.values():
        assert pytest.approx(v, 1e-6) == 1.0 / 8.0


def test_monotonic_thresholds_valid() -> None:
    """Verify strictly monotonic thresholds pass validation."""
    thresh = RiskThresholdsConfig(
        monitored_threshold=0.2,
        restricted_threshold=0.4,
        approval_threshold=0.7,
        block_threshold=0.9,
    )
    assert thresh.monitored_threshold == 0.2
    assert thresh.block_threshold == 0.9


def test_monotonic_thresholds_invalid_raises() -> None:
    """Verify out-of-order thresholds raise ValidationError."""
    with pytest.raises(ValidationError):
        # Monitored is greater than approval
        RiskThresholdsConfig(
            monitored_threshold=0.8,
            restricted_threshold=0.5,
            approval_threshold=0.4,
            block_threshold=0.9,
        )


def test_invalid_secret_key() -> None:
    """Verify too short secret keys are rejected."""
    with pytest.raises(ValidationError):
        ShieldConfig(secret_key="short")
