"""Configuration models for AgentShield SDK using Pydantic."""

from typing import Dict, List

from pydantic import BaseModel, Field, field_validator, model_validator


class RiskWeightsConfig(BaseModel):
    """Configurable weights for the 8 dynamic risk factors.

    All weights must be non-negative and are normalized to sum to 1.0.
    """
    tool_criticality: float = Field(0.20, ge=0.0)
    data_sensitivity: float = Field(0.15, ge=0.0)
    user_intent: float = Field(0.15, ge=0.0)
    prompt_injection: float = Field(0.20, ge=0.0)
    behavioral: float = Field(0.10, ge=0.0)
    historical: float = Field(0.05, ge=0.0)
    chain_dependency: float = Field(0.10, ge=0.0)
    operation_risk: float = Field(0.05, ge=0.0)

    def normalized(self) -> Dict[str, float]:
        """Return weights dictionary normalized to sum to 1.0."""
        d = self.model_dump()
        total = sum(d.values())
        if total <= 0:
            count = len(d)
            return dict.fromkeys(d, 1.0 / count)
        return {k: v / total for k, v in d.items()}


class RiskThresholdsConfig(BaseModel):
    """Thresholds determining autonomy level mapping from normalized risk."""
    monitored_threshold: float = Field(0.35, ge=0.0, le=1.0)
    restricted_threshold: float = Field(0.50, ge=0.0, le=1.0)
    approval_threshold: float = Field(0.65, ge=0.0, le=1.0)
    block_threshold: float = Field(0.85, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def verify_order(self) -> "RiskThresholdsConfig":
        if not (self.monitored_threshold <= self.restricted_threshold <= self.approval_threshold <= self.block_threshold):
            raise ValueError(
                "Thresholds must be strictly monotonic: "
                "monitored <= restricted <= approval <= block"
            )
        return self


class TrustConfig(BaseModel):
    """Configuration for Tier-Stratified Bayesian Trust management."""
    prior_alpha: float = Field(2.0, gt=0.0, description="Beta distribution prior alpha (successes)")
    prior_beta: float = Field(2.0, gt=0.0, description="Beta distribution prior beta (failures)")
    positive_weight: float = Field(1.0, gt=0.0, description="Increment on successful execution")
    negative_penalty: float = Field(3.0, gt=0.0, description="Asymmetric penalty on suspicious/failed actions")
    decay_rate: float = Field(0.01, ge=0.0, le=1.0, description="Trust decay rate over time/operations")
    min_evidence_threshold: int = Field(3, ge=1, description="Minimum evidence count before full autonomy")


class ChainRiskConfig(BaseModel):
    """Configuration for cumulative tool-chain risk tracking."""
    max_cumulative_risk: float = Field(0.85, ge=0.0, le=1.0)
    session_decay: float = Field(0.95, ge=0.0, le=1.0)
    max_history_steps: int = Field(50, ge=5)


class ShieldConfig(BaseModel):
    """Master configuration for the AgentShield SDK."""
    enabled: bool = Field(True, description="Master enable/disable switch")
    default_deny: bool = Field(True, description="Default to deny for unregistered tools")
    secret_key: str = Field(
        "agentshield-default-secret-key-change-in-production",
        description="Secret key for signing approval digests and HMACs",
    )
    audit_db_path: str = Field(
        ":memory:",
        description="Path to SQLite audit database or :memory:",
    )
    risk_weights: RiskWeightsConfig = Field(default_factory=RiskWeightsConfig)
    thresholds: RiskThresholdsConfig = Field(default_factory=RiskThresholdsConfig)
    trust: TrustConfig = Field(default_factory=TrustConfig)
    chain_risk: ChainRiskConfig = Field(default_factory=ChainRiskConfig)
    registered_tools: List[str] = Field(
        default_factory=lambda: ["read_file", "list_files", "search", "echo"],
        description="List of initially allowed registered tools",
    )
    strict_mode: bool = Field(False, description="Enforce zero-tolerance security rules")

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if not v or len(v.strip()) < 8:
            raise ValueError("secret_key must be at least 8 characters long")
        return v
