"""Dynamic 8-factor risk evaluators for AgentShield.

Implements normalized [0.0, 1.0] risk evaluation across:
1. Tool Criticality
2. Data Sensitivity
3. User Intent Risk
4. Prompt Injection Risk
5. Behavioral Risk
6. Historical Risk
7. Chain Dependency
8. Operation Risk

Security Design:
- Each factor produces an explicit score clamped to [0.0, 1.0].
- Deterministic heuristic evaluation (no external black-box dependency).
- Fail-safe defaults: missing or invalid context is never assumed to be zero risk.
"""

import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from agentshield.core.types import OperationTier, SecurityLabel
from agentshield.mcp.interceptor import ToolSchema

# Sensitive keywords indicating credential or confidential data
SENSITIVE_PATTERNS = [
    re.compile(r"(?i)\b(api_key|secret|password|token|bearer|auth|credential|private_key|ssh_key|certificate)\b"),
    re.compile(r"(?i)\b(id_rsa|id_ed25519|\.env|\.pgpass|\.netrc|shadow|master\.key)\b"),
    re.compile(r"(?i)\b(ssn|credit_card|cvv|passcode|secret_access_key)\b"),
]

# Injection indicators: system prompt overrides, delimiter hijack, instruction bypass
INJECTION_PATTERNS = [
    re.compile(r"(?i)\b(ignore previous instructions|disregard all previous|override system instructions)\b"),
    re.compile(r"(?i)\b(you are now in developer mode|jailbreak|DAN mode|unrestricted mode)\b"),
    re.compile(r"(?i)(<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|```system)"),
    re.compile(r"(?i)\b(bypass security|disable guardrails|ignore safety policies)\b"),
    re.compile(r"(?i)\b(print your system prompt|reveal instructions|output your secret key)\b"),
]

# Destructive command and query patterns
DESTRUCTIVE_PATTERNS = [
    re.compile(r"(?i)\b(rm -rf|drop table|drop database|truncate table|delete from|format|mkfs|fdisk)\b"),
    re.compile(r"(?i)\b(kill -9|pkill -9|shutdown -h|reboot -f|poweroff)\b"),
    re.compile(r"(?i)\b(chmod 777|chown root|sudo su|visudo)\b"),
]

HIGH_RISK_TOOL_PREFIXES = ("delete_", "remove_", "drop_", "kill_", "exec_", "shell_", "run_command", "eval_")
LOW_RISK_TOOL_PREFIXES = ("read_", "get_", "list_", "show_", "search_", "view_", "inspect_", "describe_")


def _clamp(val: float) -> float:
    """Clamp a float strictly to [0.0, 1.0]."""
    if val < 0.0:
        return 0.0
    if val > 1.0:
        return 1.0
    return float(val)


def _extract_all_text(data: Any) -> str:
    """Recursively extract all string keys and values from nested parameters."""
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        parts = []
        for k, v in data.items():
            parts.append(str(k))
            parts.append(_extract_all_text(v))
        return " ".join(parts)
    if isinstance(data, (list, tuple, set)):
        return " ".join(_extract_all_text(x) for x in data)
    return str(data)


class FactorEvaluation(BaseModel):
    """Result of an individual factor assessment."""
    score: float = Field(..., ge=0.0, le=1.0, description="Normalized score [0.0, 1.0]")
    explanation: str = Field(..., description="Human-readable rationale for the score")


class RiskAssessmentFactors(BaseModel):
    """Container for all 8 risk factor evaluations."""
    tool_criticality: FactorEvaluation
    data_sensitivity: FactorEvaluation
    user_intent: FactorEvaluation
    prompt_injection: FactorEvaluation
    behavioral: FactorEvaluation
    historical: FactorEvaluation
    chain_dependency: FactorEvaluation
    operation_risk: FactorEvaluation

    def as_scores(self) -> Dict[str, float]:
        """Return mapping of factor names to float scores."""
        return {
            "tool_criticality": self.tool_criticality.score,
            "data_sensitivity": self.data_sensitivity.score,
            "user_intent": self.user_intent.score,
            "prompt_injection": self.prompt_injection.score,
            "behavioral": self.behavioral.score,
            "historical": self.historical.score,
            "chain_dependency": self.chain_dependency.score,
            "operation_risk": self.operation_risk.score,
        }

    def as_explanations(self) -> Dict[str, str]:
        """Return mapping of factor names to explanations."""
        return {
            "tool_criticality": self.tool_criticality.explanation,
            "data_sensitivity": self.data_sensitivity.explanation,
            "user_intent": self.user_intent.explanation,
            "prompt_injection": self.prompt_injection.explanation,
            "behavioral": self.behavioral.explanation,
            "historical": self.historical.explanation,
            "chain_dependency": self.chain_dependency.explanation,
            "operation_risk": self.operation_risk.explanation,
        }

    def highest_factor(self) -> tuple[str, float]:
        """Return the name and score of the highest risk factor."""
        scores = self.as_scores()
        top_name = max(scores, key=lambda k: scores[k])
        return top_name, scores[top_name]


def evaluate_tool_criticality(
    tool_name: str,
    schema: Optional[ToolSchema] = None,
) -> FactorEvaluation:
    """Factor 1: Assess inherent criticality of the tool [0.0, 1.0]."""
    if not tool_name or not isinstance(tool_name, str):
        return FactorEvaluation(
            score=0.50,
            explanation="Unspecified tool name; fail-safe moderate criticality assigned",
        )

    clean_name = tool_name.lower().strip()

    if schema and schema.operation_tier:
        tier_scores = {
            OperationTier.LOW: (0.10, "Configured as LOW tier (read-only / safe inspection)"),
            OperationTier.MEDIUM: (0.40, "Configured as MEDIUM tier (state-modifying writes)"),
            OperationTier.HIGH: (0.75, "Configured as HIGH tier (external network or sensitive access)"),
            OperationTier.CRITICAL: (1.00, "Configured as CRITICAL tier (system modification or destructive action)"),
        }
        score, reason = tier_scores.get(schema.operation_tier, (0.50, "Unrecognized tier"))
        return FactorEvaluation(score=_clamp(score), explanation=reason)

    if clean_name.startswith(HIGH_RISK_TOOL_PREFIXES):
        return FactorEvaluation(
            score=0.90,
            explanation=f"Tool name '{tool_name}' matches high-risk operation prefix",
        )
    if clean_name.startswith(LOW_RISK_TOOL_PREFIXES):
        return FactorEvaluation(
            score=0.15,
            explanation=f"Tool name '{tool_name}' matches low-risk inspection prefix",
        )

    return FactorEvaluation(
        score=0.50,
        explanation=f"Tool '{tool_name}' unclassified; fail-safe default criticality assigned",
    )


def evaluate_data_sensitivity(
    arguments: Optional[Dict[str, Any]] = None,
    schema: Optional[ToolSchema] = None,
) -> FactorEvaluation:
    """Factor 2: Assess data classification and presence of confidential tokens [0.0, 1.0]."""
    score = 0.05
    reasons = []

    if schema and schema.security_label:
        label_scores = {
            SecurityLabel.PUBLIC: (0.05, "Security label: PUBLIC"),
            SecurityLabel.INTERNAL: (0.30, "Security label: INTERNAL"),
            SecurityLabel.CONFIDENTIAL: (0.70, "Security label: CONFIDENTIAL"),
            SecurityLabel.CREDENTIAL: (0.95, "Security label: CREDENTIAL"),
        }
        s, r = label_scores.get(schema.security_label, (0.05, "Default label"))
        score = s
        reasons.append(r)

    if arguments is None:
        if not reasons:
            return FactorEvaluation(
                score=0.30,
                explanation="No arguments provided; fail-safe internal sensitivity assumed",
            )
        return FactorEvaluation(score=_clamp(score), explanation="; ".join(reasons))

    all_text = _extract_all_text(arguments)
    matched_patterns = []
    for pattern in SENSITIVE_PATTERNS:
        matches = pattern.findall(all_text)
        if matches:
            matched_patterns.extend(matches[:3])

    if matched_patterns:
        score = max(score, 0.90)
        reasons.append(f"Detected sensitive keywords/tokens: {', '.join(set(matched_patterns))}")
    elif not reasons:
        reasons.append("No sensitive keywords detected in parameters")

    return FactorEvaluation(score=_clamp(score), explanation="; ".join(reasons))


def evaluate_user_intent_risk(
    user_intent: Optional[str] = None,
    arguments: Optional[Dict[str, Any]] = None,
) -> FactorEvaluation:
    """Factor 3: Assess user intent and purpose risk [0.0, 1.0]."""
    if not user_intent or not user_intent.strip():
        return FactorEvaluation(
            score=0.25,
            explanation="No explicit user intent provided; unverified ambient intent assigned",
        )

    text = f"{user_intent} {_extract_all_text(arguments)}"

    for pattern in DESTRUCTIVE_PATTERNS:
        match = pattern.search(text)
        if match:
            return FactorEvaluation(
                score=0.95,
                explanation=f"Explicit destructive intent pattern detected: '{match.group(0)}'",
            )

    for pattern in INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            return FactorEvaluation(
                score=0.90,
                explanation=f"Adversarial or prompt injection intent detected: '{match.group(0)}'",
            )

    high_risk_words = ("force", "bypass", "escalate", "override", "dump", "exfiltrate", "kill")
    detected = [w for w in high_risk_words if re.search(rf"\b{w}\b", text, re.I)]

    if len(detected) >= 2:
        return FactorEvaluation(
            score=0.80,
            explanation=f"Multiple high-risk intent markers detected: {', '.join(detected)}",
        )
    if len(detected) == 1:
        return FactorEvaluation(
            score=0.50,
            explanation=f"Moderate risk intent marker detected: '{detected[0]}'",
        )

    return FactorEvaluation(
        score=0.10,
        explanation="User intent aligns with standard, benign operational requests",
    )


def evaluate_prompt_injection_risk(
    arguments: Optional[Dict[str, Any]] = None,
    raw_prompt: Optional[str] = None,
) -> FactorEvaluation:
    """Factor 4: Detect prompt injection patterns and delimiter escapes [0.0, 1.0]."""
    text = f"{raw_prompt or ''} {_extract_all_text(arguments)}".strip()
    if not text:
        return FactorEvaluation(
            score=0.05,
            explanation="Empty input; minimal baseline injection risk",
        )

    matched_indicators = []
    for pattern in INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            matched_indicators.append(match.group(0))

    if len(matched_indicators) >= 2:
        return FactorEvaluation(
            score=0.95,
            explanation=f"Multiple prompt injection indicators detected: {', '.join(matched_indicators)}",
        )
    if len(matched_indicators) == 1:
        return FactorEvaluation(
            score=0.75,
            explanation=f"Prompt injection indicator detected: '{matched_indicators[0]}'",
        )

    return FactorEvaluation(
        score=0.05,
        explanation="No injection patterns matched heuristic rules (heuristic boundaries apply)",
    )


def evaluate_behavioral_risk(
    agent_id: str = "default_agent",
    tool_name: str = "",
    session_history: Optional[List[Dict[str, Any]]] = None,
) -> FactorEvaluation:
    """Factor 5: Detect abnormal tool invocation patterns and call spikes [0.0, 1.0]."""
    if not session_history:
        return FactorEvaluation(
            score=0.20,
            explanation="Initial session state; insufficient behavioral history",
        )

    recent_calls = session_history[-10:]
    same_tool_count = sum(1 for call in recent_calls if call.get("tool_name") == tool_name)

    if same_tool_count > 6:
        return FactorEvaluation(
            score=0.85,
            explanation=f"High behavioral anomaly: tool '{tool_name}' invoked {same_tool_count} times in last 10 calls",
        )
    if same_tool_count > 4:
        return FactorEvaluation(
            score=0.55,
            explanation=f"Moderate behavioral repetition: tool '{tool_name}' invoked {same_tool_count} times recently",
        )

    return FactorEvaluation(
        score=0.15,
        explanation="Tool invocation frequency and distribution within normal operational parameters",
    )


def evaluate_historical_risk(
    session_violations: int = 0,
    session_total: int = 0,
) -> FactorEvaluation:
    """Factor 6: Assess past failure and violation rate [0.0, 1.0]."""
    if session_total <= 0:
        return FactorEvaluation(
            score=0.20,
            explanation="Zero previous operations recorded for session",
        )

    if session_violations < 0:
        session_violations = 0

    violation_rate = min(1.0, session_violations / session_total)

    if violation_rate > 0.5:
        return FactorEvaluation(
            score=0.90,
            explanation=f"Critical historical failure rate: {violation_rate:.1%} of session operations had violations",
        )
    if violation_rate > 0.2:
        return FactorEvaluation(
            score=0.60,
            explanation=f"Elevated historical failure rate: {violation_rate:.1%} of operations had violations",
        )
    if session_violations > 0:
        return FactorEvaluation(
            score=0.35,
            explanation=f"Session has recorded {session_violations} past violation(s)",
        )

    return FactorEvaluation(
        score=0.05,
        explanation="Clean session history with zero security violations",
    )


def evaluate_chain_dependency(
    tool_name: str = "",
    schema: Optional[ToolSchema] = None,
    previous_tools: Optional[List[str]] = None,
) -> FactorEvaluation:
    """Factor 7: Assess cumulative chain dependency (e.g. read_credential -> network_sink) [0.0, 1.0]."""
    if not previous_tools:
        return FactorEvaluation(
            score=0.10,
            explanation="Initial tool in execution chain; no prior dependencies",
        )

    is_sink = False
    if schema and schema.is_sink:
        is_sink = True
    elif any(tool_name.lower().startswith(p) for p in ("send_", "post_", "upload_", "curl", "network_", "webhook_")):
        is_sink = True

    has_sensitive_read = any(
        any(prev.lower().startswith(p) for p in ("read_", "get_", "fetch_", "dump_"))
        and any(w in prev.lower() for w in ("secret", "key", "credential", "auth", "password", "token", "shadow"))
        for prev in previous_tools
    )

    if is_sink and has_sensitive_read:
        return FactorEvaluation(
            score=0.95,
            explanation="Exfiltration chain pattern: network egress sink invoked following sensitive credential read",
        )

    chain_len = len(previous_tools)
    if chain_len > 20:
        return FactorEvaluation(
            score=0.45,
            explanation=f"Extended tool-chain length ({chain_len} prior operations)",
        )
    if chain_len > 10:
        return FactorEvaluation(
            score=0.25,
            explanation=f"Moderate tool-chain length ({chain_len} prior operations)",
        )

    return FactorEvaluation(
        score=0.10,
        explanation="Tool-chain dependencies and sequence within standard bounds",
    )


def evaluate_operation_risk(
    tool_name: str = "",
    arguments: Optional[Dict[str, Any]] = None,
) -> FactorEvaluation:
    """Factor 8: Assess destructiveness, reversibility, and blast radius [0.0, 1.0]."""
    text = f"{tool_name} {_extract_all_text(arguments)}"

    for pattern in DESTRUCTIVE_PATTERNS:
        match = pattern.search(text)
        if match:
            return FactorEvaluation(
                score=0.95,
                explanation=f"Destructive or irreversible command detected: '{match.group(0)}'",
            )

    clean_name = tool_name.lower().strip()
    if clean_name.startswith(("delete_", "remove_", "drop_", "truncate_", "wipe_", "destroy_")):
        return FactorEvaluation(
            score=0.85,
            explanation=f"Tool '{tool_name}' performs destructive deletion/removal",
        )
    if clean_name.startswith(("write_", "update_", "modify_", "put_", "patch_", "create_")):
        return FactorEvaluation(
            score=0.40,
            explanation=f"Tool '{tool_name}' modifies persistent state or files",
        )
    if clean_name.startswith(LOW_RISK_TOOL_PREFIXES):
        return FactorEvaluation(
            score=0.10,
            explanation=f"Tool '{tool_name}' is read-only and idempotent",
        )

    return FactorEvaluation(
        score=0.30,
        explanation=f"Tool '{tool_name}' has standard operation risk",
    )


def evaluate_all_factors(
    tool_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    schema: Optional[ToolSchema] = None,
    user_intent: Optional[str] = None,
    raw_prompt: Optional[str] = None,
    agent_id: str = "default_agent",
    session_history: Optional[List[Dict[str, Any]]] = None,
    session_violations: int = 0,
    session_total: int = 0,
    previous_tools: Optional[List[str]] = None,
) -> RiskAssessmentFactors:
    """Evaluate all 8 risk factors comprehensively."""
    return RiskAssessmentFactors(
        tool_criticality=evaluate_tool_criticality(tool_name, schema),
        data_sensitivity=evaluate_data_sensitivity(arguments, schema),
        user_intent=evaluate_user_intent_risk(user_intent, arguments),
        prompt_injection=evaluate_prompt_injection_risk(arguments, raw_prompt),
        behavioral=evaluate_behavioral_risk(agent_id, tool_name, session_history),
        historical=evaluate_historical_risk(session_violations, session_total),
        chain_dependency=evaluate_chain_dependency(tool_name, schema, previous_tools),
        operation_risk=evaluate_operation_risk(tool_name, arguments),
    )
