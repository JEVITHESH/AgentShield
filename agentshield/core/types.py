"""Core types, enumerations, and data models for AgentShield SDK."""

from enum import Enum, IntEnum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class SecurityLabel(str, Enum):
    """Information flow security lattice labels.

    Lattice order: PUBLIC < INTERNAL < CONFIDENTIAL < CREDENTIAL.
    """
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    CREDENTIAL = "credential"

    @property
    def level(self) -> int:
        """Integer representation for lattice order comparison."""
        mapping = {
            SecurityLabel.PUBLIC: 0,
            SecurityLabel.INTERNAL: 1,
            SecurityLabel.CONFIDENTIAL: 2,
            SecurityLabel.CREDENTIAL: 3,
        }
        return mapping[self]

    def can_flow_to(self, target: "SecurityLabel") -> bool:
        """Check if information at self can flow to target without declassification.

        Information flow policy: no read up, no write down (Bell-LaPadula / Biba variant).
        Data at label L1 may flow to L2 if L1 <= L2.
        """
        return self.level <= target.level

    def __le__(self, other: Any) -> bool:
        if not isinstance(other, SecurityLabel):
            return NotImplemented
        return self.level <= other.level

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, SecurityLabel):
            return NotImplemented
        return self.level < other.level

    def __ge__(self, other: Any) -> bool:
        if not isinstance(other, SecurityLabel):
            return NotImplemented
        return self.level >= other.level

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, SecurityLabel):
            return NotImplemented
        return self.level > other.level


class AutonomyLevel(IntEnum):
    """Granular 5-level autonomy classification for AI agents.

    Higher risk must never increase autonomy.
    Higher trust may increase autonomy only within policy limits.
    """
    L0_BLOCK = 0
    L1_APPROVAL = 1
    L2_RESTRICTED = 2
    L3_MONITORED = 3
    L4_AUTONOMOUS = 4

    @property
    def label(self) -> str:
        labels = {
            AutonomyLevel.L0_BLOCK: "L0: Block",
            AutonomyLevel.L1_APPROVAL: "L1: Human Approval",
            AutonomyLevel.L2_RESTRICTED: "L2: Restricted",
            AutonomyLevel.L3_MONITORED: "L3: Monitored",
            AutonomyLevel.L4_AUTONOMOUS: "L4: Autonomous",
        }
        return labels[self]


class OperationTier(str, Enum):
    """Operation criticality tiers for stratified Bayesian trust tracking.

    Maintaining trust independently per tier prevents low-tier trust farming.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityDecision(str, Enum):
    """High-level security outcome for an intercepted operation."""
    ALLOW = "allow"
    MONITOR = "monitor"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


class ProtectionResult(BaseModel):
    """Result returned by AgentShield when inspecting or executing a tool call."""
    allowed: bool = Field(..., description="Whether the operation is permitted to execute")
    decision: SecurityDecision = Field(..., description="Categorical security decision")
    autonomy_level: AutonomyLevel = Field(..., description="Autonomy level assigned to operation")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Overall normalized risk [0.0, 1.0]")
    trust_score: float = Field(..., ge=0.0, le=1.0, description="Current Bayesian trust score [0.0, 1.0]")
    tool_name: str = Field(..., description="Target tool name")
    reason: str = Field(default="", description="Human-readable decision explanation")
    approval_id: Optional[str] = Field(default=None, description="Approval ID if approval is required")
    digest: Optional[str] = Field(default=None, description="Cryptographic integrity digest")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic and audit metadata")
