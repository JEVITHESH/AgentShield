"""AgentShield: MCP AI Agent Security SDK.

A dynamic security and autonomy-control middleware for protecting MCP-based autonomous AI agents.
"""

from agentshield.core.config import (
    ChainRiskConfig,
    RiskThresholdsConfig,
    RiskWeightsConfig,
    ShieldConfig,
    TrustConfig,
)
from agentshield.core.engine import AgentShield
from agentshield.core.exceptions import (
    AgentShieldError,
    ApprovalRejectedError,
    ApprovalRequiredError,
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
from agentshield.core.types import (
    AutonomyLevel,
    OperationTier,
    ProtectionResult,
    SecurityDecision,
    SecurityLabel,
)
from agentshield.mcp.client import ShieldedMCPClient
from agentshield.mcp.interceptor import ToolInterceptor, ToolRequest, ToolSchema
from agentshield.mcp.middleware import MCPMiddleware
from agentshield.risk.engine import (
    RiskAssessment,
    RiskCategory,
    RiskEngine,
)
from agentshield.risk.factors import (
    FactorEvaluation,
    RiskAssessmentFactors,
)

__version__ = "0.1.0"

__all__ = [
    "AgentShield",
    "AgentShieldError",
    "ApprovalRejectedError",
    "ApprovalRequiredError",
    "ApprovalRequiredException",
    "ApprovalTimeoutError",
    "AuditLoggingError",
    "AutonomyLevel",
    "ChainRiskConfig",
    "ConfigurationError",
    "CumulativeRiskExceededError",
    "DataLeakageError",
    "FactorEvaluation",
    "IntegrityCheckFailedError",
    "MCPMiddleware",
    "OperationTier",
    "PromptInjectionDetectedError",
    "ProtectionResult",
    "RiskAssessment",
    "RiskAssessmentFactors",
    "RiskCategory",
    "RiskEngine",
    "RiskThresholdsConfig",
    "RiskWeightsConfig",
    "SecurityDecision",
    "SecurityLabel",
    "SecurityViolationError",
    "ShieldConfig",
    "ShieldedMCPClient",
    "ToolExecutionError",
    "ToolInterceptor",
    "ToolRequest",
    "ToolSchema",
    "TrustConfig",
    "UnauthorizedToolError",
    "__version__",
]
