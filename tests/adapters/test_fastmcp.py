"""Tests for FastMCP adapter."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mcp_armor.adapters.fastmcp import wrap_fastmcp, _GuardedToolDispatcher
from mcp_armor.guard import CoSAIGuard
from mcp_armor.engines.session import SessionEngine
from mcp_armor.exceptions import AuthorizationError


def _guard() -> CoSAIGuard:
    return CoSAIGuard([SessionEngine(bind_to_dpop=False)])


# ---------------------------------------------------------------------------
# Helpers — fake FastMCP module and instances
# ---------------------------------------------------------------------------

def _fake_fastmcp_module():
    """Build a fake fastmcp module whose FastMCP class supports isinstance()."""
    class FakeFastMCP:
        pass

    fake_module = MagicMock()
    fake_module.FastMCP = FakeFastMCP
    return fake_module, FakeFastMCP


# ---------------------------------------------------------------------------
# wrap_fastmcp — ASGI composition
# ---------------------------------------------------------------------------

def test_wrap_fastmcp_missing_import_raises() -> None:
    """Without fastmcp installed the adapter must raise ImportError immediately."""
    with patch.dict("sys.modules", {"fastmcp": None}):
        with pytest.raises(ImportError, match="fastmcp"):
            wrap_fastmcp(MagicMock(), _guard())


def test_wrap_fastmcp_uses_http_app_for_v2() -> None:
    """FastMCP ≥ 2.x: wrap_fastmcp calls app.http_app() to get the ASGI app."""
    from mcp_armor.adapters.fastapi import ArmorMiddleware

    fake_module, FakeFastMCP = _fake_fastmcp_module()
    asgi_inner = MagicMock()
    fake_app = FakeFastMCP()
    fake_app.http_app = MagicMock(return_value=asgi_inner)

    with patch.dict("sys.modules", {"fastmcp": fake_module}):
        result = wrap_fastmcp(fake_app, _guard())

    fake_app.http_app.assert_called_once()
    assert isinstance(result, ArmorMiddleware)


def test_wrap_fastmcp_falls_back_to_app_attr() -> None:
    """FastMCP 1.x: wrap_fastmcp uses app.app when http_app() is not available."""
    from mcp_armor.adapters.fastapi import ArmorMiddleware

    fake_module, FakeFastMCP = _fake_fastmcp_module()
    asgi_inner = MagicMock()
    fake_app = FakeFastMCP()
    fake_app.app = asgi_inner
    # No http_app attribute on this instance

    with patch.dict("sys.modules", {"fastmcp": fake_module}):
        result = wrap_fastmcp(fake_app, _guard())
    assert isinstance(result, ArmorMiddleware)


def test_wrap_fastmcp_unknown_app_type_raises() -> None:
    """An object that is not a FastMCP instance raises TypeError before attribute checks."""
    fake_module, FakeFastMCP = _fake_fastmcp_module()
    not_fastmcp = MagicMock()  # not an instance of FakeFastMCP

    with patch.dict("sys.modules", {"fastmcp": fake_module}):
        with pytest.raises(TypeError, match="FastMCP instance"):
            wrap_fastmcp(not_fastmcp, _guard())


# ---------------------------------------------------------------------------
# _GuardedToolDispatcher
# ---------------------------------------------------------------------------

async def test_guarded_tool_calls_fn_when_guard_passes() -> None:
    """When guard chain passes, the original tool function is called."""
    dispatcher = _GuardedToolDispatcher(CoSAIGuard([]))  # no engines

    result_holder: list[str] = []

    async def my_tool(query: str) -> str:
        result_holder.append(query)
        return f"result:{query}"

    wrapped = dispatcher.hook(my_tool)
    out = await wrapped(query="hello")
    assert out == "result:hello"
    assert result_holder == ["hello"]


async def test_guarded_tool_raises_when_guard_rejects() -> None:
    """When an engine raises CoSAIException, the wrapped tool must raise it too."""

    class RejectAllEngine:
        async def on_startup(self) -> None: pass
        async def on_session_start(self, ctx): return ctx
        async def on_request(self, ctx, req): raise AuthorizationError("always rejected")
        async def on_response(self, ctx, resp): return ctx
        async def on_session_end(self, ctx) -> None: pass
        async def on_shutdown(self) -> None: pass

    dispatcher = _GuardedToolDispatcher(CoSAIGuard([RejectAllEngine()]))

    async def my_tool() -> str:
        return "should not reach"

    wrapped = dispatcher.hook(my_tool)
    with pytest.raises(AuthorizationError, match="always rejected"):
        await wrapped()


async def test_guarded_tool_closes_session_on_success() -> None:
    """close_session must be called on success (T7-004)."""
    closed: list[str] = []

    class TrackCloseEngine(SessionEngine):
        async def on_session_end(self, ctx) -> None:
            closed.append(ctx.session_id)

    dispatcher = _GuardedToolDispatcher(CoSAIGuard([TrackCloseEngine(bind_to_dpop=False)]))

    async def my_tool() -> str:
        return "ok"

    wrapped = dispatcher.hook(my_tool)
    await wrapped()
    assert len(closed) == 1


async def test_guarded_tool_closes_session_on_response_error() -> None:
    """close_session must be called even when response-phase engine raises."""
    closed: list[str] = []

    from mcp_armor.exceptions import InjectionDetectedError

    class RejectResponseEngine:
        async def on_startup(self) -> None: pass
        async def on_session_start(self, ctx): return ctx
        async def on_request(self, ctx, req): return ctx
        async def on_response(self, ctx, resp): raise InjectionDetectedError("bad response")
        async def on_session_end(self, ctx) -> None: pass
        async def on_shutdown(self) -> None: pass

    class TrackCloseEngine(SessionEngine):
        async def on_session_end(self, ctx) -> None:
            closed.append(ctx.session_id)

    dispatcher = _GuardedToolDispatcher(
        CoSAIGuard([RejectResponseEngine(), TrackCloseEngine(bind_to_dpop=False)])
    )

    async def my_tool() -> str:
        return "jailbreak content"

    wrapped = dispatcher.hook(my_tool)
    with pytest.raises(InjectionDetectedError):
        await wrapped()
    assert len(closed) == 1


# ---------------------------------------------------------------------------
# Panel regression tests
# ---------------------------------------------------------------------------

async def test_regression_close_session_fires_when_run_request_raises() -> None:
    """FIX-1: close_session must fire even when _run_request raises (before fn executes)."""
    closed: list[str] = []

    class RejectRequestEngine:
        async def on_startup(self) -> None: pass
        async def on_session_start(self, ctx): return ctx
        async def on_request(self, ctx, req): raise AuthorizationError("rejected at request")
        async def on_response(self, ctx, resp): return ctx
        async def on_session_end(self, ctx) -> None: pass
        async def on_shutdown(self) -> None: pass

    class TrackCloseEngine(SessionEngine):
        async def on_session_end(self, ctx) -> None:
            closed.append(ctx.session_id)

    dispatcher = _GuardedToolDispatcher(
        CoSAIGuard([RejectRequestEngine(), TrackCloseEngine(bind_to_dpop=False)])
    )

    async def my_tool() -> str:
        return "unreachable"

    wrapped = dispatcher.hook(my_tool)
    with pytest.raises(AuthorizationError):
        await wrapped()
    assert len(closed) == 1, "close_session must fire even when _run_request raises"


async def test_regression_hook_transport_propagated_to_context() -> None:
    """FIX-2: transport param on hook() must flow through to CoSAIContext and MCPRequest."""
    observed: list[str] = []

    class TransportSpyEngine:
        async def on_startup(self) -> None: pass
        async def on_session_start(self, ctx):
            observed.append(f"session:{ctx.transport}")
            return ctx
        async def on_request(self, ctx, req):
            observed.append(f"req:{req.transport}")
            return ctx
        async def on_response(self, ctx, resp): return ctx
        async def on_session_end(self, ctx) -> None: pass
        async def on_shutdown(self) -> None: pass

    dispatcher = _GuardedToolDispatcher(CoSAIGuard([TransportSpyEngine()]))

    async def my_tool() -> str:
        return "ok"

    wrapped = dispatcher.hook(my_tool, transport="http")
    await wrapped()
    assert "session:http" in observed
    assert "req:http" in observed


def test_regression_wrap_fastmcp_rejects_non_fastmcp_type() -> None:
    """FIX-3: non-FastMCP objects must be rejected with TypeError before attribute introspection."""
    fake_module, FakeFastMCP = _fake_fastmcp_module()

    class ImposterApp:
        def http_app(self): return MagicMock()

    with patch.dict("sys.modules", {"fastmcp": fake_module}):
        with pytest.raises(TypeError, match="FastMCP instance"):
            wrap_fastmcp(ImposterApp(), _guard())


async def test_regression_guarded_tool_raw_body_is_html_escaped() -> None:
    """FIX-5: tool return value must be HTML-escaped before passing to response engines."""
    received_bodies: list[str] = []

    class BodySpyEngine:
        async def on_startup(self) -> None: pass
        async def on_session_start(self, ctx): return ctx
        async def on_request(self, ctx, req): return ctx
        async def on_response(self, ctx, resp):
            received_bodies.append(resp.raw_body)
            return ctx
        async def on_session_end(self, ctx) -> None: pass
        async def on_shutdown(self) -> None: pass

    dispatcher = _GuardedToolDispatcher(CoSAIGuard([BodySpyEngine()]))

    async def my_tool() -> str:
        return "<script>alert(1)</script>"

    wrapped = dispatcher.hook(my_tool)
    await wrapped()

    assert len(received_bodies) == 1
    # Must be HTML-escaped — raw "<script>" must not appear
    assert "<script>" not in received_bodies[0]
    assert "&lt;script&gt;" in received_bodies[0]
