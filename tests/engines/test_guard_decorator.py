"""Tests for Fix 2 — @guard.protect ContextVar ASGI context propagation."""

from __future__ import annotations

import pytest

from mcp_armor.context import CoSAIContext
from mcp_armor.guard import CoSAIGuard, _active_ctx
from tests.conftest import make_ctx


def _minimal_guard() -> CoSAIGuard:
    """A guard with no engines that would block a basic call."""
    return CoSAIGuard([])  # no engines — we test context propagation, not engine logic


# ---------------------------------------------------------------------------
# Fix 2 — ASGI context propagation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_protect_decorator_uses_active_asgi_context() -> None:
    """
    When _active_ctx ContextVar is set (simulating an ASGI request), the
    @guard.protect wrapper must use the live CoSAIContext (with its scopes)
    rather than creating a blank stdio context.
    If required_scope='read' and the ASGI context has 'read' in scopes, it must NOT raise.
    """
    guard = _minimal_guard()
    # Build a context that has the required scope
    asgi_ctx = make_ctx(transport="http")
    asgi_ctx_with_scope = asgi_ctx.with_scopes(("read", "write"))

    # Set the ContextVar to simulate an active ASGI request
    token = _active_ctx.set(asgi_ctx_with_scope)
    try:

        @guard.protect(required_scope="read")
        async def my_tool(name: str) -> str:
            return f"hello {name}"

        result = await my_tool(name="world")
        assert result == "hello world"
    finally:
        _active_ctx.reset(token)


@pytest.mark.asyncio
async def test_protect_decorator_asgi_context_scope_enforced() -> None:
    """
    When the ASGI context does NOT have the required scope, AuthorizationError
    must be raised even though _active_ctx is set.
    """
    from mcp_armor.exceptions import AuthorizationError

    guard = _minimal_guard()
    asgi_ctx = make_ctx(transport="http")
    asgi_ctx_no_scope = asgi_ctx.with_scopes(("write",))  # no 'admin' scope

    token = _active_ctx.set(asgi_ctx_no_scope)
    try:

        @guard.protect(required_scope="admin")
        async def admin_tool() -> str:
            return "secret"

        with pytest.raises(AuthorizationError, match="admin"):
            await admin_tool()
    finally:
        _active_ctx.reset(token)


@pytest.mark.asyncio
async def test_protect_decorator_falls_back_to_stdio_when_no_asgi_context() -> None:
    """
    When no ASGI context is set (_active_ctx is None / default), the decorator
    must fall back to creating a fresh stdio context without crashing.
    """
    # Ensure no active context
    token = _active_ctx.set(None)
    try:
        guard = CoSAIGuard([])  # no engines — nothing to block

        @guard.protect()
        async def simple_tool(x: int) -> int:
            return x * 2

        result = await simple_tool(x=5)
        assert result == 10
    finally:
        _active_ctx.reset(token)


@pytest.mark.asyncio
async def test_protect_decorator_stdio_mode_no_required_scope() -> None:
    """
    In stdio mode (no ASGI context), a tool without required_scope must execute
    normally.
    """
    guard = CoSAIGuard([])  # no engines

    @guard.protect()
    async def echo(msg: str) -> str:
        return msg

    result = await echo(msg="ping")
    assert result == "ping"


# ---------------------------------------------------------------------------
# Fix 3 — threats= filter must not drop AuthzEngine/AuthEngine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exploit_protect_threats_filter_keeps_authz() -> None:
    """
    @guard.protect(threats=['T3']) must still run AuthzEngine (T2 scope check),
    not silently drop it from the active engine list.
    """
    from mcp_armor.config import T2Config, ToolPolicy
    from mcp_armor.engines.authz import AuthzEngine
    from mcp_armor.engines.validation import ValidationEngine
    from mcp_armor.exceptions import AuthorizationError

    t2 = T2Config(
        tool_policies={
            "secret_tool": ToolPolicy(
                required_scopes=("admin",),
                user_only=False,
                destructive=False,
                tenant_isolated=False,
            )
        },
        default_deny=False,
        destructive_token_ttl_seconds=60,
        echo_confirm_token=False,
    )
    authz = AuthzEngine(
        tool_policies=t2.tool_policies,
        default_deny=t2.default_deny,
        destructive_token_ttl_seconds=t2.destructive_token_ttl_seconds,
        echo_confirm_token=t2.echo_confirm_token,
    )
    validation = ValidationEngine()
    # Guard with both engines; developer restricts to T3 only via threats
    guard = CoSAIGuard([authz, validation])

    asgi_ctx = make_ctx(transport="http")
    # Context has no 'admin' scope — AuthzEngine must still fire
    asgi_ctx_no_scope = asgi_ctx.with_scopes(("read",))
    token = _active_ctx.set(asgi_ctx_no_scope)
    try:

        @guard.protect(threats=["T3"])  # developer forgot T2
        async def secret_tool() -> str:
            return "secret"

        # AuthzEngine must still enforce the scope check
        with pytest.raises(AuthorizationError):
            await secret_tool()
    finally:
        _active_ctx.reset(token)


# ---------------------------------------------------------------------------
# Fix 8 — ContextVar reset after ASGI request completes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_active_ctx_no_bleed() -> None:
    """After _handle_http completes, _active_ctx must be reset to None."""
    import json

    from mcp_armor.adapters.fastapi import ArmorMiddleware
    from mcp_armor.guard import _active_ctx as armor_ctx

    guard = CoSAIGuard([])

    # Minimal ASGI app that returns a valid JSON-RPC response
    async def dummy_app(scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode()
        await send({"type": "http.response.body", "body": body, "more_body": False})

    middleware = ArmorMiddleware(dummy_app, guard, cors_origins=["http://localhost"])

    sent_messages: list[dict] = []

    async def capture_send(msg: dict) -> None:
        sent_messages.append(msg)

    initialize_body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    ).encode()

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [
            (b"content-type", b"application/json"),
            (b"origin", b"http://localhost"),
        ],
        "query_string": b"",
    }
    body_messages = iter(
        [
            {"type": "http.request", "body": initialize_body, "more_body": False},
        ]
    )

    async def mock_receive() -> dict:
        try:
            return next(body_messages)
        except StopIteration:
            return {"type": "http.disconnect"}

    # _active_ctx must be None before the request
    assert armor_ctx.get() is None

    await middleware._handle_http(scope, mock_receive, capture_send)

    # _active_ctx must be reset to None after _handle_http returns
    ctx_after = armor_ctx.get()
    assert ctx_after is None, f"_active_ctx leaked after request: {ctx_after!r}"


# ---------------------------------------------------------------------------
# Fix 10 — _GuardedToolDispatcher propagates _armor_active_ctx
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_guarded_tool_dispatcher_propagates_active_ctx() -> None:
    """
    Tools dispatched through _GuardedToolDispatcher.hook() must see the correct
    CoSAIContext in _armor_active_ctx inside the decorated tool body.
    """
    from mcp_armor.adapters.fastmcp import _GuardedToolDispatcher
    from mcp_armor.guard import _active_ctx as armor_ctx

    guard = CoSAIGuard([])  # no engines that would block
    dispatcher = _GuardedToolDispatcher(guard)

    captured_ctx: list = []

    @dispatcher.hook
    async def my_tool(x: int) -> int:
        # Capture whatever _active_ctx holds during tool execution
        captured_ctx.append(armor_ctx.get())
        return x + 1

    result = await my_tool(x=5)
    assert result == 6

    # _active_ctx must have been populated with a real CoSAIContext (not None)
    assert len(captured_ctx) == 1
    assert isinstance(captured_ctx[0], CoSAIContext), (
        f"_active_ctx was {captured_ctx[0]!r} inside dispatched tool — expected CoSAIContext"
    )
