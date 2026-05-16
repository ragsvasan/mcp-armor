"""Tests for T7 SessionEngine — stateless HMAC binding.

Covers fixation (T7-001), URL leak (T7-002), cross-transport replay (T7-003),
and the deliberate stateless model (T7-004), plus the cross-instance survival
that the old in-memory store could not provide.
"""

from __future__ import annotations

from types import MappingProxyType

import pytest

from mcp_armor.engines._session_token import _MIN_SECRET_BYTES, SessionSigner
from mcp_armor.engines.session import SessionEngine
from mcp_armor.exceptions import SessionError
from mcp_armor.guard import CoSAIGuard
from mcp_armor.types import MCPRequest
from tests.conftest import make_ctx, make_request

_SECRET = b"k" * _MIN_SECRET_BYTES


def _engine(secret: bytes = _SECRET) -> SessionEngine:
    return SessionEngine(bind_to_dpop=False, signer=SessionSigner(secret))


def _ctx_for(eng: SessionEngine, transport: str = "http"):
    """A context whose session_id is a valid token minted by `eng`."""
    token = eng.signer.mint(transport)
    return make_ctx(token, transport=transport), token


# --------------------------------------------------------------------------- #
# Fixation prevention (T7-001)
# --------------------------------------------------------------------------- #

async def test_minted_session_passes_on_request() -> None:
    eng = _engine()
    ctx, token = _ctx_for(eng)
    req = make_request(method="tools/call", session_id=token)
    assert await eng.on_request(ctx, req) is not None


async def test_unknown_session_id_rejected() -> None:
    eng = _engine()
    ctx = make_ctx("attacker-chosen-id")
    req = make_request(method="tools/call", session_id="attacker-chosen-id")
    with pytest.raises(SessionError):
        await eng.on_request(ctx, req)


async def test_initialize_with_forged_session_rejected() -> None:
    """An attacker sending 'initialize' with a fabricated session_id must be
    rejected — the signature check applies on every method, not just non-init."""
    eng = _engine()
    ctx = make_ctx("attacker-session")
    req = make_request(method="initialize", session_id="attacker-session")
    with pytest.raises(SessionError):
        await eng.on_request(ctx, req)


async def test_initialize_on_minted_session_passes() -> None:
    eng = _engine()
    ctx, token = _ctx_for(eng)
    req = make_request(method="initialize", session_id=token)
    assert await eng.on_request(ctx, req) is not None


# --------------------------------------------------------------------------- #
# Cross-instance survival — the production incident
# --------------------------------------------------------------------------- #

async def test_session_minted_on_one_engine_verifies_on_another() -> None:
    """Instance A mints, request lands on instance B (fresh SessionEngine, same
    secret). The store-based engine raised T7-001 here; the signed token must
    verify."""
    instance_a = _engine(_SECRET)
    instance_b = _engine(_SECRET)
    token = instance_a.signer.mint("http")
    ctx = make_ctx(token, transport="http")
    req = make_request(method="tools/call", session_id=token, transport="http")
    assert await instance_b.on_request(ctx, req) is not None


async def test_session_rejected_across_engines_with_different_secret() -> None:
    instance_a = _engine(_SECRET)
    instance_b = _engine(b"different" + b"q" * _MIN_SECRET_BYTES)
    token = instance_a.signer.mint("http")
    ctx = make_ctx(token, transport="http")
    req = make_request(method="tools/call", session_id=token, transport="http")
    with pytest.raises(SessionError):
        await instance_b.on_request(ctx, req)


# --------------------------------------------------------------------------- #
# Cross-transport replay (T7-003)
# --------------------------------------------------------------------------- #

async def test_same_transport_passes() -> None:
    eng = _engine()
    token = eng.signer.mint("http")
    ctx = make_ctx(token, transport="http")
    req = make_request(method="tools/call", session_id=token, transport="http")
    assert await eng.on_request(ctx, req) is not None


async def test_transport_change_rejected() -> None:
    eng = _engine()
    token = eng.signer.mint("http")  # minted for http
    ctx = make_ctx(token, transport="stdio")
    req = make_request(method="tools/call", session_id=token, transport="stdio")
    with pytest.raises(SessionError):
        await eng.on_request(ctx, req)


async def test_stdio_session_round_trip_does_not_raise() -> None:
    eng = _engine()
    token = eng.signer.mint("stdio")
    ctx = make_ctx(token, transport="stdio")
    req = make_request(method="tools/call", session_id=token, transport="stdio")
    assert await eng.on_request(ctx, req) is not None


# --------------------------------------------------------------------------- #
# URL session_id leak (T7-002) — preserved from the store model
# --------------------------------------------------------------------------- #

def _url_req(token: str, params: dict) -> MCPRequest:
    return MCPRequest(
        method="tools/call",
        params=MappingProxyType({}),
        session_id=token,
        raw_headers=MappingProxyType({}),
        url_query_params=MappingProxyType(params),
    )


async def test_session_id_in_url_params_rejected() -> None:
    eng = _engine()
    token = eng.signer.mint("http")
    ctx = make_ctx(token, transport="http")
    with pytest.raises(SessionError, match="URL"):
        await eng.on_request(ctx, _url_req(token, {"session_id": token}))


async def test_mcp_session_id_in_url_params_rejected() -> None:
    eng = _engine()
    token = eng.signer.mint("http")
    ctx = make_ctx(token, transport="http")
    with pytest.raises(SessionError, match="URL"):
        await eng.on_request(ctx, _url_req(token, {"mcp_session_id": token}))


async def test_unrelated_url_params_allowed() -> None:
    eng = _engine()
    token = eng.signer.mint("http")
    ctx = make_ctx(token, transport="http")
    assert await eng.on_request(ctx, _url_req(token, {"page": "1"})) is not None


# --------------------------------------------------------------------------- #
# Stateless model (T7-004)
# --------------------------------------------------------------------------- #

async def test_session_start_and_end_are_noops() -> None:
    eng = _engine()
    ctx, _ = _ctx_for(eng)
    assert await eng.on_session_start(ctx) is ctx
    assert await eng.on_session_end(ctx) is None  # no state to clear


async def test_stateless_no_server_side_revocation() -> None:
    """Deliberate behaviour change vs the store model: a signed token has no
    server-side record, so on_session_end does NOT invalidate it. Session
    *revocation* is delegated to the auth/token layer (T1) — T7's job is
    issuance binding, and statelessness is what makes it survive scaling.
    T7-004 (context bleed) is satisfied structurally: there is no state."""
    eng = _engine()
    ctx, token = _ctx_for(eng)
    await eng.on_session_end(ctx)
    req = make_request(method="tools/call", session_id=token)
    assert await eng.on_request(ctx, req) is not None


# --------------------------------------------------------------------------- #
# Guard integration — mint_session_id wiring
# --------------------------------------------------------------------------- #

async def test_guard_mint_session_id_uses_session_engine_signer() -> None:
    eng = _engine()
    guard = CoSAIGuard([eng])
    token = guard.mint_session_id("http")
    ctx = make_ctx(token, transport="http")
    req = make_request(method="tools/call", session_id=token, transport="http")
    assert await eng.on_request(ctx, req) is not None


def test_guard_mint_session_id_falls_back_to_uuid_without_session_engine() -> None:
    guard = CoSAIGuard([])  # T7 disabled — no SessionEngine
    sid = guard.mint_session_id("http")
    assert "." not in sid and "-" in sid  # a UUID, not a signed token


def test_session_engine_construction_fails_closed_without_secret(monkeypatch) -> None:
    monkeypatch.delenv("ARMOR_SESSION_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="ARMOR_SESSION_SECRET is not set"):
        SessionEngine(bind_to_dpop=False)


async def test_regression_protect_tool_works_with_t7_session_engine_enabled() -> None:
    """Defense FIX[1]: guard.protect()'s wrapper used to mint a raw uuid; with
    T7 enabled SessionEngine.on_request then verified that uuid and raised
    SessionError on every decorated tool. It must now mint a signed token."""
    guard = CoSAIGuard([_engine()])

    @guard.protect()  # no threats filter → SessionEngine is in the active set
    async def my_tool(x: int) -> int:
        return x + 1

    assert await my_tool(41) == 42  # must not raise SessionError
