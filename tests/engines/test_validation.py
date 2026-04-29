"""Tests for ValidationEngine — T3 injection scans and schema validation."""

from __future__ import annotations

import pytest

from mcp_armor.engines.validation import ValidationEngine
from mcp_armor.exceptions import ValidationError
from tests.conftest import make_ctx, make_request


def _req(tool: str, arguments: dict, *, method: str = "tools/call"):
    return make_request(
        method=method,
        params={"name": tool, "arguments": arguments},
    )


# ---------------------------------------------------------------------------
# T3-001: size limit
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_regression_oversized_payload_raises():
    engine = ValidationEngine(max_payload_bytes=10)
    ctx = make_ctx()
    req = _req("search", {"q": "x" * 100})
    with pytest.raises(ValidationError, match="Payload exceeds"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_payload_within_limit_passes():
    engine = ValidationEngine(max_payload_bytes=65_536, strict_schema=False)
    ctx = make_ctx()
    req = _req("search", {"q": "hello"})
    result = await engine.on_request(ctx, req)
    assert result is ctx


# ---------------------------------------------------------------------------
# T3-002: command injection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("value", [
    "ls; rm -rf /",
    "$(cat /etc/passwd)",
    "foo | bar",
    "cmd `whoami`",
    "exec(os.system('ls'))",
    "eval('import os')",
])
async def test_regression_cmd_injection_blocked(value):
    engine = ValidationEngine()
    ctx = make_ctx()
    req = _req("run", {"cmd": value})
    with pytest.raises(ValidationError, match="injection"):
        await engine.on_request(ctx, req)


# ---------------------------------------------------------------------------
# T3-003: path traversal
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("value", [
    "../etc/passwd",
    "../../secret",
    "/etc/passwd",
    "%2e%2e/secret",
    "..\\windows\\system32",
])
async def test_regression_path_traversal_blocked(value):
    engine = ValidationEngine()
    ctx = make_ctx()
    req = _req("read_file", {"path": value})
    with pytest.raises(ValidationError, match="injection|traversal"):
        await engine.on_request(ctx, req)


# ---------------------------------------------------------------------------
# T3-004: SQL injection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("value", [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "1 UNION SELECT * FROM secrets",
    "1; DELETE FROM accounts",
])
async def test_regression_sql_injection_blocked(value):
    engine = ValidationEngine()
    ctx = make_ctx()
    req = _req("db_query", {"q": value})
    with pytest.raises(ValidationError, match="injection"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_clean_string_args_pass_injection_scan():
    engine = ValidationEngine(strict_schema=False)
    ctx = make_ctx()
    req = _req("search", {"query": "find all widgets in category furniture"})
    result = await engine.on_request(ctx, req)
    assert result is ctx


# ---------------------------------------------------------------------------
# T3-005: JSON schema validation
# ---------------------------------------------------------------------------

_SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {"type": "string"},
        "limit": {"type": "integer"},
    },
    "required": ["query"],
}


@pytest.mark.asyncio
async def test_schema_valid_args_pass():
    engine = ValidationEngine(strict_schema=True)
    engine.register_tools([{"name": "search", "inputSchema": _SEARCH_SCHEMA}])
    ctx = make_ctx()
    req = _req("search", {"query": "hello", "limit": 10})
    result = await engine.on_request(ctx, req)
    assert result is ctx


@pytest.mark.asyncio
async def test_regression_schema_unknown_field_strict_raises():
    engine = ValidationEngine(strict_schema=True)
    engine.register_tools([{"name": "search", "inputSchema": _SEARCH_SCHEMA}])
    ctx = make_ctx()
    req = _req("search", {"query": "hi", "extra_field": "bad"})
    with pytest.raises(ValidationError, match="schema violation"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_regression_schema_missing_required_field_raises():
    engine = ValidationEngine(strict_schema=True)
    engine.register_tools([{"name": "search", "inputSchema": _SEARCH_SCHEMA}])
    ctx = make_ctx()
    req = _req("search", {"limit": 5})  # missing required "query"
    with pytest.raises(ValidationError, match="schema violation"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_schema_wrong_type_raises():
    engine = ValidationEngine(strict_schema=True)
    engine.register_tools([{"name": "search", "inputSchema": _SEARCH_SCHEMA}])
    ctx = make_ctx()
    req = _req("search", {"query": 42})  # query must be string
    with pytest.raises(ValidationError, match="schema violation"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_schema_not_registered_strict_mode_fails_closed():
    """P2: strict_schema=True with unregistered tool must fail closed — not skip silently."""
    engine = ValidationEngine(strict_schema=True)
    ctx = make_ctx()
    req = _req("unknown_tool", {"anything": "goes"})
    with pytest.raises(ValidationError, match="no registered schema"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_non_tools_call_method_skips_validation():
    engine = ValidationEngine()
    ctx = make_ctx()
    req = make_request(method="tools/list", params={})
    result = await engine.on_request(ctx, req)
    assert result is ctx


# ---------------------------------------------------------------------------
# register_tools
# ---------------------------------------------------------------------------

def test_register_tools_stores_schemas():
    engine = ValidationEngine()
    tools = [
        {"name": "alpha", "inputSchema": {"type": "object"}},
        {"name": "beta", "inputSchema": {"type": "object", "properties": {"x": {}}}},
        {"name": "noschema"},  # inputSchema absent — should not crash
    ]
    engine.register_tools(tools)
    assert "alpha" in engine._tool_schemas
    assert "beta" in engine._tool_schemas
    assert "noschema" in engine._tool_schemas
    assert engine._tool_schemas["noschema"] == {}


# ---------------------------------------------------------------------------
# FIX[2]: Non-dict arguments must be rejected, not silently skipped
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_regression_non_dict_arguments_raises():
    """arguments as a plain string must raise, even with no schema registered."""
    engine = ValidationEngine(strict_schema=False)
    ctx = make_ctx()
    req = make_request(
        method="tools/call",
        params={"name": "run_cmd", "arguments": "; rm -rf /"},
    )
    with pytest.raises(ValidationError, match="must be an object"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_regression_non_dict_args_list_raises():
    engine = ValidationEngine(strict_schema=False)
    ctx = make_ctx()
    req = make_request(
        method="tools/call",
        params={"name": "run_cmd", "arguments": ["ls", "; rm -rf /"]},
    )
    with pytest.raises(ValidationError, match="must be an object"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_none_arguments_passes():
    """arguments=None is allowed (tool with no inputs)."""
    engine = ValidationEngine(strict_schema=False)
    ctx = make_ctx()
    req = make_request(
        method="tools/call",
        params={"name": "ping"},
    )
    result = await engine.on_request(ctx, req)
    assert result is ctx


# ---------------------------------------------------------------------------
# FIX[7]: Nested strings inside lists and dicts must be scanned
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_regression_nested_list_injection_blocked():
    """Injection inside a list element must be caught."""
    engine = ValidationEngine()
    ctx = make_ctx()
    req = _req("run", {"cmds": ["ls", "ls; rm -rf /"]})
    with pytest.raises(ValidationError, match="injection"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_regression_nested_dict_injection_blocked():
    """Injection inside a nested dict value must be caught."""
    engine = ValidationEngine()
    ctx = make_ctx()
    req = _req("read", {"config": {"path": "../etc/passwd"}})
    with pytest.raises(ValidationError, match="injection|traversal"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_regression_deeply_nested_injection_blocked():
    engine = ValidationEngine()
    ctx = make_ctx()
    req = _req("multi", {"level1": {"level2": ["safe", "'; DROP TABLE users; --"]}})
    with pytest.raises(ValidationError, match="injection"):
        await engine.on_request(ctx, req)


# ---------------------------------------------------------------------------
# FIX[4]: SQL -- comment patterns
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("value", [
    "SELECT 1--\nDROP TABLE users",
    "admin'-- comment here",
    "' OR 1=1--x",
    "username--",
])
async def test_regression_sql_inline_comment_blocked(value):
    engine = ValidationEngine()
    ctx = make_ctx()
    req = _req("db_query", {"q": value})
    with pytest.raises(ValidationError, match="injection"):
        await engine.on_request(ctx, req)


# ---------------------------------------------------------------------------
# FIX[5]: Shell redirect and Windows bypass patterns
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("value", [
    "ls > /tmp/out",
    "ls < /etc/passwd",
    "${IFS}whoami",
    "cmd /c dir",
    "%COMSPEC%",
])
async def test_regression_cmd_redirect_blocked(value):
    engine = ValidationEngine()
    ctx = make_ctx()
    req = _req("run", {"cmd": value})
    with pytest.raises(ValidationError, match="injection"):
        await engine.on_request(ctx, req)


# ---------------------------------------------------------------------------
# FIX[6]: Sensitive path patterns beyond /etc/passwd
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("value", [
    "/etc/crontab",
    "/etc/environment",
    "/root/.ssh/id_rsa",
    "/home/user/.ssh/authorized_keys",
    "C:\\Windows\\System32\\cmd.exe",
])
async def test_regression_sensitive_path_blocked(value):
    engine = ValidationEngine()
    ctx = make_ctx()
    req = _req("read_file", {"path": value})
    with pytest.raises(ValidationError, match="injection|traversal"):
        await engine.on_request(ctx, req)


# ---------------------------------------------------------------------------
# FIX[8]: SQL numeric tautology
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("value", [
    "1 OR 1=1",
    "0 OR 0=0",
    "1 AND 2=2",
])
async def test_regression_sql_numeric_tautology_blocked(value):
    engine = ValidationEngine()
    ctx = make_ctx()
    req = _req("db_query", {"q": value})
    with pytest.raises(ValidationError, match="injection"):
        await engine.on_request(ctx, req)


# ---------------------------------------------------------------------------
# Codex P2: strict_schema fail-closed on unregistered tools
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_regression_strict_schema_unregistered_tool_raises() -> None:
    """P2: strict_schema=True with no registered schema must fail closed (T3-005)."""
    engine = ValidationEngine(strict_schema=True)
    ctx = make_ctx()
    req = _req("unregistered_tool", {"param": "value"})
    with pytest.raises(ValidationError, match="no registered schema"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_regression_strict_schema_registered_empty_schema_passes() -> None:
    """P2: strict_schema=True with registered empty schema must pass (no restrictions)."""
    engine = ValidationEngine(strict_schema=True)
    engine.register_tools([{"name": "my_tool", "inputSchema": {}}])
    ctx = make_ctx()
    req = _req("my_tool", {"anything": "goes"})
    # Empty schema {} means no restrictions — must not raise
    result = await engine.on_request(ctx, req)
    assert result is ctx


@pytest.mark.asyncio
async def test_regression_strict_schema_registered_schema_enforced() -> None:
    """P2: strict_schema=True with registered schema must reject invalid args."""
    engine = ValidationEngine(strict_schema=True)
    engine.register_tools([{
        "name": "my_tool",
        "inputSchema": {
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"],
        },
    }])
    ctx = make_ctx()
    req = _req("my_tool", {"not_q": "wrong"})
    with pytest.raises(ValidationError):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_regression_strict_schema_false_allows_unregistered_tool() -> None:
    """P2: strict_schema=False must not raise for unregistered tools."""
    engine = ValidationEngine(strict_schema=False)
    ctx = make_ctx()
    req = _req("unknown_tool", {"anything": "goes"})
    result = await engine.on_request(ctx, req)
    assert result is ctx
