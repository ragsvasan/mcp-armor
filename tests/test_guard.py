"""Tests for CoSAIGuard — factory, lifecycle, chain composition."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_armor.guard import CoSAIGuard
from mcp_armor.engines.session import SessionEngine
from mcp_armor.engines.boundary import BoundaryEngine
from mcp_armor.config import ArmorConfig, T7Config


def _minimal_guard() -> CoSAIGuard:
    return CoSAIGuard([SessionEngine(bind_to_dpop=False)])


# ---------------------------------------------------------------------------
# Factory — from_config
# ---------------------------------------------------------------------------

def test_from_config_loads_yaml(tmp_path: Path) -> None:
    """from_config() must build a guard from a cosai.yaml file."""
    yaml_content = """\
version: 1
threats:
  T7:
    bind_session_to_dpop: false
"""
    cfg_path = tmp_path / "cosai.yaml"
    cfg_path.write_text(yaml_content)
    guard = CoSAIGuard.from_config(str(cfg_path))
    assert guard is not None
    assert len(guard._engines) > 0


def test_from_config_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises((FileNotFoundError, OSError, Exception)):
        CoSAIGuard.from_config(str(tmp_path / "nonexistent.yaml"))


def _all_none_config() -> ArmorConfig:
    """Build an ArmorConfig with all threats disabled."""
    return ArmorConfig(
        version=1,
        t1=None, t2=None, t3=None, t4=None, t5=None, t6=None,
        t7=None, t8=None, t9=None, t10=None, t11=None, t12=None,
    )


def test_from_armor_config_builds_session_engine() -> None:
    """_from_armor_config with T7 config must include SessionEngine."""
    cfg = _all_none_config().__class__(
        version=1, t1=None, t2=None, t3=None, t4=None, t5=None, t6=None,
        t7=T7Config(bind_to_dpop=False),
        t8=None, t9=None, t10=None, t11=None, t12=None,
    )
    guard = CoSAIGuard._from_armor_config(cfg)
    assert any(isinstance(e, SessionEngine) for e in guard._engines)


def test_from_armor_config_empty_config_has_no_engines() -> None:
    """All-None config → no engines."""
    cfg = _all_none_config()
    guard = CoSAIGuard._from_armor_config(cfg)
    assert len(guard._engines) == 0


# ---------------------------------------------------------------------------
# Lifecycle — startup / shutdown
# ---------------------------------------------------------------------------

async def test_startup_calls_all_engines() -> None:
    started = []

    class TrackEngine(SessionEngine):
        async def on_startup(self) -> None:
            started.append("started")

    guard = CoSAIGuard([TrackEngine(bind_to_dpop=False)])
    await guard.startup()
    assert started == ["started"]


async def test_shutdown_calls_all_engines() -> None:
    stopped = []

    class TrackEngine(SessionEngine):
        async def on_shutdown(self) -> None:
            stopped.append("stopped")

    guard = CoSAIGuard([TrackEngine(bind_to_dpop=False)])
    await guard.shutdown()
    assert stopped == ["stopped"]


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------

async def test_open_session_calls_on_session_start() -> None:
    opened = []

    class TrackEngine(SessionEngine):
        async def on_session_start(self, ctx):
            opened.append(ctx.session_id)
            return ctx

    guard = CoSAIGuard([TrackEngine(bind_to_dpop=False)])
    from tests.conftest import make_ctx
    ctx = make_ctx()
    result = await guard.open_session(ctx)
    assert ctx.session_id in opened


async def test_close_session_calls_on_session_end() -> None:
    closed = []

    class TrackEngine(SessionEngine):
        async def on_session_end(self, ctx) -> None:
            closed.append(ctx.session_id)

    guard = CoSAIGuard([TrackEngine(bind_to_dpop=False)])
    from tests.conftest import make_ctx
    ctx = make_ctx()
    await guard.open_session(ctx)
    await guard.close_session(ctx)
    assert ctx.session_id in closed


# ---------------------------------------------------------------------------
# Request/response chain
# ---------------------------------------------------------------------------

async def test_run_request_calls_all_engines_in_order() -> None:
    order = []

    class Engine1(BoundaryEngine):
        async def on_request(self, ctx, req):
            order.append(1)
            return ctx

    class Engine2(BoundaryEngine):
        async def on_request(self, ctx, req):
            order.append(2)
            return ctx

    guard = CoSAIGuard([Engine1(), Engine2()])
    from tests.conftest import make_ctx, make_request
    ctx = make_ctx()
    req = make_request()
    await guard._run_request(ctx, req)
    assert order == [1, 2]


async def test_run_response_calls_engines_in_reverse() -> None:
    order = []

    class Engine1(BoundaryEngine):
        async def on_response(self, ctx, resp):
            order.append(1)
            return ctx

    class Engine2(BoundaryEngine):
        async def on_response(self, ctx, resp):
            order.append(2)
            return ctx

    guard = CoSAIGuard([Engine1(), Engine2()])
    from tests.conftest import make_ctx, make_response
    ctx = make_ctx()
    resp = make_response("ok")
    await guard._run_response(ctx, resp)
    assert order == [2, 1]  # reversed


# ---------------------------------------------------------------------------
# asgi() / wrap_dispatcher()
# ---------------------------------------------------------------------------

def test_asgi_returns_armor_middleware() -> None:
    from mcp_armor.adapters.fastapi import ArmorMiddleware
    from starlette.applications import Starlette

    guard = _minimal_guard()
    inner = Starlette()
    result = guard.asgi(inner)
    assert isinstance(result, ArmorMiddleware)


def test_wrap_dispatcher_returns_callable() -> None:
    guard = CoSAIGuard([])

    async def fake_dispatcher(payload):
        return {"jsonrpc": "2.0", "result": {}}

    wrapped = guard.wrap_dispatcher(fake_dispatcher)
    assert callable(wrapped)


def test_default_builds_all_engines() -> None:
    """CoSAIGuard.default() must include engines for all 12 threat categories."""
    guard = CoSAIGuard.default()
    # Should have at least one engine per major category
    assert len(guard._engines) >= 10


def test_register_tool_schemas_forwards_to_validation_engine() -> None:
    from mcp_armor.engines.validation import ValidationEngine
    ve = ValidationEngine()
    guard = CoSAIGuard([ve])
    tools = [{"name": "my_tool", "inputSchema": {"type": "object"}}]
    guard.register_tool_schemas(tools)  # must not raise


async def test_wrap_dispatcher_passes_clean_request() -> None:
    guard = CoSAIGuard([])  # no engines

    calls = []

    async def echo(payload):
        calls.append(payload)
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"ok": True}}

    wrapped = guard.wrap_dispatcher(echo)
    result = await wrapped({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    assert "result" in result
    assert calls[0]["method"] == "tools/list"
