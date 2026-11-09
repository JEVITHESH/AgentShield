"""Unit tests for MCP ToolInterceptor, normalization, schema validation, and hooks."""

import pytest

from agentshield.core.exceptions import SecurityViolationError
from agentshield.mcp.interceptor import ToolInterceptor, ToolRequest, ToolSchema


def test_argument_normalization() -> None:
    """Verify whitespace stripping and key sorting during normalization."""
    interceptor = ToolInterceptor()
    raw = {
        "  path  ": "   /etc/shadow   ",
        "nested": {"  inner_key ": "  value  ", "a": 123},
        "items": ["  hello ", " world "],
    }
    normalized = interceptor.normalize_arguments(raw)

    assert normalized["  path  "] == "/etc/shadow"
    assert normalized["nested"]["  inner_key "] == "value"
    assert normalized["items"] == ["hello", "world"]


def test_schema_validation_required_field_missing() -> None:
    """Verify error raised when required argument is missing."""
    interceptor = ToolInterceptor()
    schema = ToolSchema(
        name="read_file",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    )
    req = ToolRequest(tool_name="read_file", arguments={})

    with pytest.raises(SecurityViolationError) as exc_info:
        interceptor.validate_request(req, schema)
    assert "missing required argument: 'path'" in str(exc_info.value)


def test_schema_validation_disallowed_properties() -> None:
    """Verify unexpected arguments rejected if additionalProperties is False."""
    interceptor = ToolInterceptor()
    schema = ToolSchema(
        name="echo",
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "additionalProperties": False,
        },
    )
    req = ToolRequest(tool_name="echo", arguments={"text": "hi", "injected_param": "malicious"})

    with pytest.raises(SecurityViolationError) as exc_info:
        interceptor.validate_request(req, schema)
    assert "received disallowed arguments" in str(exc_info.value)


def test_schema_validation_type_mismatch() -> None:
    """Verify type checking catches incorrect argument types."""
    interceptor = ToolInterceptor()
    schema = ToolSchema(
        name="compute",
        input_schema={
            "type": "object",
            "properties": {"count": {"type": "integer"}, "enabled": {"type": "boolean"}},
        },
    )
    # Boolean passed where integer expected
    req1 = ToolRequest(tool_name="compute", arguments={"count": True})
    with pytest.raises(SecurityViolationError):
        interceptor.validate_request(req1, schema)

    # String passed where integer expected
    req2 = ToolRequest(tool_name="compute", arguments={"count": "not_an_int"})
    with pytest.raises(SecurityViolationError):
        interceptor.validate_request(req2, schema)


def test_interceptor_lifecycle_hooks() -> None:
    """Verify pre-, post-, and error hooks execute properly."""
    interceptor = ToolInterceptor()
    events = []

    def pre_hook(r: ToolRequest) -> ToolRequest:
        events.append(f"pre:{r.tool_name}")
        r.arguments["hook_injected"] = True
        return r

    def post_hook(r: ToolRequest, res: str) -> str:
        events.append(f"post:{res}")
        return f"{res}_modified"

    def err_hook(r: ToolRequest, e: Exception) -> None:
        events.append(f"err:{type(e).__name__}")

    interceptor.register_pre_hook(pre_hook)
    interceptor.register_post_hook(post_hook)
    interceptor.register_error_hook(err_hook)

    # Run pre
    req = ToolRequest(tool_name="test_tool", arguments={"base": "123"})
    processed_req = interceptor.intercept_pre(req)
    assert processed_req.arguments["hook_injected"] is True
    assert "pre:test_tool" in events

    # Run post
    result = interceptor.intercept_post(processed_req, "initial_result")
    assert result == "initial_result_modified"
    assert "post:initial_result" in events

    # Run error
    interceptor.intercept_error(req, ValueError("sample error"))
    assert "err:ValueError" in events
