"""Dynamic 8-Factor Risk Assessment Engine for AgentShield."""

import time
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from agentshield.core.config import RiskThresholdsConfig, RiskWeightsConfig
from agentshield.mcp.interceptor import ToolRequest, ToolSchema
from agentshield.risk.factors import (
    RiskAssessmentFactors,
    evaluate_all_factors,
)


class RiskCategory(str, Enum):
    """Categorical risk classification based on configured thresholds."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskAssessment(BaseModel):
    """Structured, explainable risk assessment result."""
    overall_score: float = Field(..., ge=0.0, le=1.0, description="Overall weighted risk score [0.0, 1.0]")
    category: RiskCategory = Field(..., description="Categorical risk classification")
    factors: Dict[str, float] = Field(..., description="Individual factor scores [0.0, 1.0]")
    explanations: Dict[str, str] = Field(..., description="Explanations for each factor score")
    applied_weights: Dict[str, float] = Field(..., description="Normalized weights used in calculation")
    weighted_contributions: Dict[str, float] = Field(..., description="weight[i] * factor[i] contributions")
    highest_factor: str = Field(..., description="Name of the highest contributing factor")
    highest_factor_score: float = Field(..., ge=0.0, le=1.0, description="Score of highest factor")
    timestamp: float = Field(default_factory=time.time, description="Assessment epoch timestamp")
    tool_name: str = Field(..., description="Evaluated tool name")
    summary: str = Field(..., description="Human-readable assessment summary")


class RiskEngine:
    """Evaluates dynamic risk for tool operations using 8 risk factors and configurable weights."""

    def __init__(
        self,
        weights: Optional[RiskWeightsConfig] = None,
        thresholds: Optional[RiskThresholdsConfig] = None,
    ) -> None:
        """Initialize RiskEngine with configurable weights and thresholds.

        Parameters
        ----------
        weights : Optional[RiskWeightsConfig]
            Weights for the 8 risk dimensions. Defaults to standard configuration.
        thresholds : Optional[RiskThresholdsConfig]
            Thresholds for categorizing risk scores.
        """
        self.weights_config = weights or RiskWeightsConfig()
        self.thresholds = thresholds or RiskThresholdsConfig()

    def categorize_score(self, score: float) -> RiskCategory:
        """Map a numeric risk score [0.0, 1.0] to a RiskCategory."""
        clamped = max(0.0, min(1.0, float(score)))

        if clamped < self.thresholds.monitored_threshold:
            return RiskCategory.LOW
        if clamped < self.thresholds.restricted_threshold:
            return RiskCategory.MEDIUM
        if clamped < self.thresholds.block_threshold:
            return RiskCategory.HIGH
        return RiskCategory.CRITICAL

    def calculate_weighted_score(
        self,
        factor_scores: Dict[str, float],
        normalized_weights: Dict[str, float],
    ) -> float:
        """Calculate weighted score: Sum(weight[i] * factor[i]).

        Ensures score is bounded within [0.0, 1.0].
        """
        weighted_sum = 0.0
        for factor_name, weight in normalized_weights.items():
            factor_val = factor_scores.get(factor_name, 0.50)  # Fail-safe default if missing
            weighted_sum += weight * factor_val

        return max(0.0, min(1.0, round(weighted_sum, 6)))

    def assess_factors(
        self,
        factors: RiskAssessmentFactors,
        tool_name: str = "unspecified_tool",
    ) -> RiskAssessment:
        """Calculate risk assessment from pre-evaluated factors."""
        scores = factors.as_scores()
        explanations = factors.as_explanations()
        normalized_weights = self.weights_config.normalized()

        overall_score = self.calculate_weighted_score(scores, normalized_weights)
        category = self.categorize_score(overall_score)

        weighted_contributions = {
            k: round(scores.get(k, 0.50) * normalized_weights.get(k, 0.0), 6)
            for k in normalized_weights
        }

        top_factor_name, top_factor_score = factors.highest_factor()

        summary = (
            f"Risk Assessment for '{tool_name}': {category.value} (Score: {overall_score:.4f}). "
            f"Primary factor: {top_factor_name} ({top_factor_score:.2f}) - {explanations.get(top_factor_name, '')}"
        )

        return RiskAssessment(
            overall_score=overall_score,
            category=category,
            factors=scores,
            explanations=explanations,
            applied_weights=normalized_weights,
            weighted_contributions=weighted_contributions,
            highest_factor=top_factor_name,
            highest_factor_score=top_factor_score,
            timestamp=time.time(),
            tool_name=tool_name,
            summary=summary,
        )

    def assess(
        self,
        request: ToolRequest,
        schema: Optional[ToolSchema] = None,
        user_intent: Optional[str] = None,
        raw_prompt: Optional[str] = None,
        session_history: Optional[List[Dict[str, Any]]] = None,
        session_violations: int = 0,
        session_total: int = 0,
        previous_tools: Optional[List[str]] = None,
    ) -> RiskAssessment:
        """Evaluate full 8-factor risk for an intercepted tool request."""
        factors = evaluate_all_factors(
            tool_name=request.tool_name,
            arguments=request.arguments,
            schema=schema,
            user_intent=user_intent,
            raw_prompt=raw_prompt,
            agent_id=request.agent_id,
            session_history=session_history,
            session_violations=session_violations,
            session_total=session_total,
            previous_tools=previous_tools,
        )

        return self.assess_factors(factors, tool_name=request.tool_name)
