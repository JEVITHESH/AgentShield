"""MCP tool request interceptor, schema validator, and lifecycle hooks."""

import copy
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, Field

from agentshield.core.exceptions import SecurityViolationError
from agentshield.core.types import OperationTier, SecurityLabel


class ToolSchema(BaseModel):
    """Metadata and definition of an MCP tool within AgentShield."""
    name: str = Field(..., description="Tool name as registered with MCP")
    description: str = Field(default="", description="Functional description of the tool")
    input_schema: Optional[Dict[str, Any]] = Field(
        default=None,
        description="JSON schema defining expected input parameters",
    )
    operation_tier: OperationTier = Field(
        default=OperationTier.LOW,
        description="Operation criticality tier for Bayesian trust tracking",
    )
    security_label: SecurityLabel = Field(
        default=SecurityLabel.INTERNAL,
        description="Information flow label associated with data handled by this tool",
    )
    is_sink: bool = Field(
        default=False,
        description="Whether this tool acts as an egress sink (e.g., network upload, external send)",
    )
    sink_clearance: SecurityLabel = Field(
        default=SecurityLabel.PUBLIC,
        description="Maximum security classification data allowed to be emitted by this sink",
    )


class ToolRequest(BaseModel):
    """Normalized MCP tool execution request intercepted by AgentShield."""
    tool_name: str = Field(..., description="Target tool name")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool arguments")
    agent_id: str = Field(default="default_agent", description="Requesting agent identifier")
    session_id: str = Field(default="default_session", description="Session context identifier")
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique request ID")
    timestamp: float = Field(default_factory=time.time, description="Invocation epoch timestamp")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary execution metadata")


class ToolInterceptor:
    """Interceptor responsible for schema validation, parameter canonicalization, and hooks."""

    def __init__(self) -> None:
        self._pre_hooks: List[Callable[[ToolRequest], ToolRequest]] = []
        self._post_hooks: List[Callable[[ToolRequest, Any], Any]] = []
        self._error_hooks: List[Callable[[ToolRequest, Exception], None]] = []

    def register_pre_hook(self, hook: Callable[[ToolRequest], ToolRequest]) -> None:
        """Register a callback executed before tool validation and execution."""
        self._pre_hooks.append(hook)

    def register_post_hook(self, hook: Callable[[ToolRequest, Any], Any]) -> None:
        """Register a callback executed after successful tool execution."""
        self._post_hooks.append(hook)

    def register_error_hook(self, hook: Callable[[ToolRequest, Exception], None]) -> None:
        """Register a callback executed when tool execution encounters an error."""
        self._error_hooks.append(hook)

    @staticmethod
    def normalize_arguments(arguments: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Deeply normalize arguments: strip strings, sort keys, convert nulls."""
        if not arguments:
            return {}

        def _clean(val: Any) -> Any:
            if isinstance(val, str):
                return val.strip()
            if isinstance(val, dict):
                return {k: _clean(v) for k, v in sorted(val.items())}
            if isinstance(val, list):
                return [_clean(item) for item in val]
            return val

        cloned = copy.deepcopy(arguments)
        return {k: _clean(v) for k, v in sorted(cloned.items())}

    def validate_request(self, request: ToolRequest, schema: Optional[ToolSchema] = None) -> None:
        """Validate request structure and compliance against tool schema."""
        if not request.tool_name or not request.tool_name.strip():
            raise SecurityViolationError("Tool name cannot be empty")

        if schema is None or schema.input_schema is None:
            return

        json_schema = schema.input_schema
        args = request.arguments

        # 1. Check required properties
        required = json_schema.get("required", [])
        for field in required:
            if field not in args:
                raise SecurityViolationError(
                    f"Tool '{request.tool_name}' missing required argument: '{field}'",
                    details={"missing_field": field, "required": required},
                )

        # 2. Check unexpected properties if additionalProperties is False
        if json_schema.get("additionalProperties") is False:
            allowed_props = set(json_schema.get("properties", {}).keys())
            unexpected = set(args.keys()) - allowed_props
            if unexpected:
                raise SecurityViolationError(
                    f"Tool '{request.tool_name}' received disallowed arguments: {sorted(unexpected)}",
                    details={"disallowed": list(unexpected)},
                )

        # 3. Check basic primitive types if specified
        properties = json_schema.get("properties", {})
        type_mapping = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "object": dict,
            "array": list,
        }

        for prop_name, prop_spec in properties.items():
            if prop_name in args and "type" in prop_spec:
                expected_type_name = prop_spec["type"]
                expected_type = type_mapping.get(expected_type_name)
                val = args[prop_name]

                # In Python bool is a subclass of int; reject bool if integer/number expected
                if expected_type_name in ("integer", "number") and isinstance(val, bool):
                    raise SecurityViolationError(
                        f"Argument '{prop_name}' must be of type {expected_type_name}, got boolean",
                        details={"field": prop_name, "expected": expected_type_name},
                    )

                if expected_type and not isinstance(val, expected_type):
                    raise SecurityViolationError(
                        f"Argument '{prop_name}' must be of type {expected_type_name}, got {type(val).__name__}",
                        details={"field": prop_name, "expected": expected_type_name},
                    )

    def intercept_pre(self, request: ToolRequest, schema: Optional[ToolSchema] = None) -> ToolRequest:
        """Process pre-execution pipeline: normalize, validate, execute pre-hooks."""
        normalized_args = self.normalize_arguments(request.arguments)
        request = ToolRequest(
            tool_name=request.tool_name.strip(),
            arguments=normalized_args,
            agent_id=request.agent_id,
            session_id=request.session_id,
            request_id=request.request_id,
            timestamp=request.timestamp,
            metadata=request.metadata,
        )

        self.validate_request(request, schema)

        for hook in self._pre_hooks:
            request = hook(request)

        return request

    def intercept_post(self, request: ToolRequest, result: Any) -> Any:
        """Process post-execution pipeline: execute post-hooks."""
        current_result = result
        for hook in self._post_hooks:
            current_result = hook(request, current_result)
        return current_result

    def intercept_error(self, request: ToolRequest, error: Exception) -> None:
        """Execute registered error hooks upon failure."""
        for hook in self._error_hooks:
            try:
                hook(request, error)
            except Exception:
                # Do not mask original error with hook failure
                pass
