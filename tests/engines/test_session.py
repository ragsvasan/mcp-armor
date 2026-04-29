"""Tests for T7 SessionEngine — fixation, cross-transport, URL leak, context bleed."""

from __future__ import annotations

import uuid

import pytest

from mcp_armor.engines.session import SessionEngine, _SessionStore
from mcp_armor.exceptions import SessionError
from tests.conftest import make_ctx, make_request


def _engine() -> SessionEngine:
    return SessionEngine(bind_to_dpop=False)


async def _open(eng: SessionEngine, session_id: str | None = None, transport: str = "http"):
    """Register a session via on_session_start (uses ctx.transport)."""
    ctx = make_ctx(session_id or str(uuid.uuid4()), transport=transport)
    ctx = await eng.on_session_start(ctx)
    return ctx


# ---------------------------------------------------------------------------
# Session creation / fixation prevention (T7-001)
# ---------------------------------------------------------------------------

async def test_known_session_passes_on_request() -> None:
    eng = _engine()
    ctx = await _open(eng)
    req = make_request(method="tools/call", session_id=ctx.session_id)
    result = await eng.on_request(ctx, req)
    assert result is not None


async def test_unknown_session_id_rejected() -> None:
    eng = _engine()
    # Do NOT call on_session_start — session_id was never registered server-side
    ctx = make_ctx("attacker-chosen-id")
    req = make_request(method="tools/call", session_id="attacker-chosen-id")
    with pytest.raises(SessionError, match="fixation"):
        await eng.on_request(ctx, req)


async def test_initialize_also_checks_session_is_known() -> None:
    """
    Panel FIX-4 (Sonnet) / FIX-5 (Opus): 'initialize' must NOT unconditionally bypass
    the store check. An attacker sending 'initialize' with a fabricated session_id
    must be rejected.
    """
    eng = _engine()
    # Unknown session — not pre-registered via on_session_start
    ctx = make_ctx("attacker-session")
    req = make_request(method="initialize", session_id="attacker-session")
    with pytest.raises(SessionError, match="fixation"):
        await eng.on_request(ctx, req)


async def test_initialize_on_known_session_passes() -> None:
    eng = _engine()
    ctx = await _open(eng)
    req = make_request(method="initialize", session_id=ctx.session_id)
    result = await eng.on_request(ctx, req)
    assert result is not None


# ---------------------------------------------------------------------------
# Cross-transport replay (T7-003)
# ---------------------------------------------------------------------------

async def test_same_transport_passes() -> None:
    eng = _engine()
    ctx = await _open(eng, transport="http")
    req = make_request(method="tools/call", session_id=ctx.session_id, transport="http")
    result = await eng.on_request(ctx, req)
    assert result is not None


async def test_transport_change_rejected() -> None:
    """
    Panel FIX-5 (Sonnet) / FIX-3 (Opus): transport is now recorded from ctx.transport
    (not hardcoded "http"), so stdio sessions are correctly locked.
    """
    eng = _engine()
    ctx = await _open(eng, transport="http")
    req = make_request(method="tools/call", session_id=ctx.session_id, transport="stdio")
    with pytest.raises(SessionError, match="Cross-transport"):
        await eng.on_request(ctx, req)


async def test_regression_stdio_session_round_trip_does_not_raise() -> None:
    """Panel FIX-3 (Opus): stdio sessions opened as stdio must pass verify on stdio requests."""
    eng = _engine()
    ctx = await _open(eng, transport="stdio")
    req = make_request(method="tools/call", session_id=ctx.session_id, transport="stdio")
    result = await eng.on_request(ctx, req)
    assert result is not None


async def test_regression_reinitialize_same_session_verifies_transport() -> None:
    """Panel FIX-4 (Sonnet): second 'initialize' on same session verifies transport."""
    eng = _engine()
    ctx = await _open(eng, transport="http")
    # Re-initialize with wrong transport — must fail
    req = make_request(method="initialize", session_id=ctx.session_id, transport="stdio")
    with pytest.raises(SessionError, match="Cross-transport"):
        await eng.on_request(ctx, req)


# ---------------------------------------------------------------------------
# URL session_id leak (T7-002)
# ---------------------------------------------------------------------------

async def test_session_id_in_url_params_rejected() -> None:
    eng = _engine()
    ctx = await _open(eng)
    from mcp_armor.types import MCPRequest
    from types import MappingProxyType
    req = MCPRequest(
        method="tools/call",
        params=MappingProxyType({}),
        session_id=ctx.session_id,
        raw_headers=MappingProxyType({}),
        url_query_params=MappingProxyType({"session_id": ctx.session_id}),
    )
    with pytest.raises(SessionError, match="URL"):
        await eng.on_request(ctx, req)


async def test_mcp_session_id_in_url_params_rejected() -> None:
    eng = _engine()
    ctx = await _open(eng)
    from mcp_armor.types import MCPRequest
    from types import MappingProxyType
    req = MCPRequest(
        method="tools/call",
        params=MappingProxyType({}),
        session_id=ctx.session_id,
        raw_headers=MappingProxyType({}),
        url_query_params=MappingProxyType({"mcp_session_id": ctx.session_id}),
    )
    with pytest.raises(SessionError, match="URL"):
        await eng.on_request(ctx, req)


async def test_unrelated_url_params_allowed() -> None:
    eng = _engine()
    ctx = await _open(eng)
    from mcp_armor.types import MCPRequest
    from types import MappingProxyType
    req = MCPRequest(
        method="tools/call",
        params=MappingProxyType({}),
        session_id=ctx.session_id,
        raw_headers=MappingProxyType({}),
        url_query_params=MappingProxyType({"page": "1"}),
    )
    result = await eng.on_request(ctx, req)
    assert result is not None


# ---------------------------------------------------------------------------
# Context bleed prevention (T7-004)
# ---------------------------------------------------------------------------

async def test_session_cleared_on_end() -> None:
    eng = _engine()
    ctx = await _open(eng)
    assert ctx.session_id in eng._store
    await eng.on_session_end(ctx)
    assert ctx.session_id not in eng._store


async def test_closed_session_rejected_on_next_request() -> None:
    eng = _engine()
    ctx = await _open(eng)
    await eng.on_session_end(ctx)
    req = make_request(method="tools/call", session_id=ctx.session_id)
    with pytest.raises(SessionError, match="fixation"):
        await eng.on_request(ctx, req)


# ---------------------------------------------------------------------------
# _SessionStore unit tests
# ---------------------------------------------------------------------------

def test_store_create_registers_session() -> None:
    store = _SessionStore()
    store.create("s1", "http")
    assert "s1" in store


def test_store_create_different_sessions_independent() -> None:
    store = _SessionStore()
    store.create("s1", "http")
    store.create("s2", "stdio")
    store.verify("s1", "http")
    store.verify("s2", "stdio")


def test_store_set_transport_updates_transport() -> None:
    store = _SessionStore()
    store.create("s1", transport=None)
    store.set_transport("s1", "http")
    store.verify("s1", "http")


def test_store_verify_unknown_raises() -> None:
    store = _SessionStore()
    with pytest.raises(SessionError, match="fixation"):
        store.verify("unknown", "http")


def test_store_verify_transport_mismatch_raises() -> None:
    store = _SessionStore()
    store.create("s1", "http")
    with pytest.raises(SessionError, match="Cross-transport"):
        store.verify("s1", "stdio")


def test_store_verify_none_transport_skips_check() -> None:
    """Transport not yet set (None) → verify passes; check is locked in on initialize."""
    store = _SessionStore()
    store.create("s1", transport=None)
    store.verify("s1", "any-transport")  # must not raise


def test_store_close_removes_entry() -> None:
    store = _SessionStore()
    store.create("s1", "http")
    assert "s1" in store
    store.close("s1")
    assert "s1" not in store


def test_store_close_idempotent() -> None:
    store = _SessionStore()
    store.close("nonexistent")  # must not raise


# ---------------------------------------------------------------------------
# make_request transport parameter (conftest FIX-9)
# ---------------------------------------------------------------------------

def test_regression_make_request_transport_param() -> None:
    req = make_request(transport="stdio")
    assert req.transport == "stdio"
