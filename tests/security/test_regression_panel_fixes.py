"""Regression tests for the 2026-07-17 panel findings on the audit remediation.

The T1 panels (MCP-protocol persona + adversary + defense) found that several
remediation fixes were incomplete or introduced new gaps:
  1. types.py coerced non-object JSON-RPC params to {} → the guard scanned an
     empty params while the raw array/scalar was forwarded verbatim (a request
     -side scan/forward asymmetry, the same class H1 fixed on the response side).
  2. fastapi.py failed closed on a non-object body only when a *content* scanner
     was active — a tools/list that must be scope-filtered was silently skipped
     (authorization bypass).
  3. the H1 response size cap reused the 64KB request cap (rejecting legitimate
     multi-hundred-KB tool results) and was checked only AFTER the full body was
     buffered (OOM before the cap).
  4. resources.py _session_budgets grew unbounded on mint-and-abandon paths that
     never reach on_session_end (HTTP open→zombie-reap, and wrap_dispatcher).
"""

from __future__ import annotations

import json

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp_armor.adapters.fastapi import ArmorMiddleware
from mcp_armor.engines.session import SessionEngine
from mcp_armor.exceptions import ValidationError
from mcp_armor.guard import CoSAIGuard
from mcp_armor.types import MCPRequest


def _client(app: ArmorMiddleware) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )


def _payload(method: str, params=None, req_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
        "params": params if params is not None else {},
    }


# --- Finding 1: non-object params rejected (fail closed), not coerced to {} ---


def test_regression_array_params_rejected_by_from_dict() -> None:
    for bad in (["../../etc/passwd"], "scalar", 42):
        with pytest.raises(ValidationError):
            MCPRequest.from_dict(
                {"method": "resources/read", "params": bad}, session_id="s", headers={}
            )
    # object params (and absent params) still build fine
    r = MCPRequest.from_dict({"method": "x", "params": {"a": 1}}, session_id="s", headers={})
    assert dict(r.params) == {"a": 1}
    r2 = MCPRequest.from_dict({"method": "x"}, session_id="s", headers={})
    assert dict(r2.params) == {}


async def test_regression_array_params_not_forwarded_via_dispatcher() -> None:
    from mcp_armor.adapters.dispatcher import wrap_dispatcher

    seen: list = []

    async def stub(payload: dict) -> dict:
        seen.append(payload)
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {}}

    protected = wrap_dispatcher(stub, CoSAIGuard([SessionEngine()]))
    resp = await protected(
        {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": ["../../etc/passwd"]}
    )
    assert seen == [], "raw array-params payload reached the dispatcher unscanned"
    assert "error" in resp and resp["error"]["code"] == -32602


# --- Finding 2: tools/list non-object body fails closed (scope-filter bypass) ---


async def test_regression_tools_list_nonobject_body_fails_closed() -> None:
    """A non-object tools/list body must fail closed EVEN with no content scanner
    configured — the scope filter keys off resp_dict, so before the fix it was
    skipped and the raw, unfiltered tool list egress'd (authz bypass)."""

    async def _handler(request: Request) -> Response:
        payload = json.loads(await request.body())
        if payload.get("method") == "tools/list":
            return Response(
                json.dumps(["admin_tool", "internal_tool"]), media_type="application/json"
            )
        return JSONResponse({"jsonrpc": "2.0", "id": payload.get("id"), "result": {}})

    inner = Starlette(routes=[Route("/{path:path}", _handler, methods=["POST"])])
    app = ArmorMiddleware(inner, CoSAIGuard([SessionEngine()]))  # no content scanner

    async with _client(app) as client:
        init = await client.post("/", json=_payload("initialize"))
        sid = init.headers["mcp-session-id"]
        resp = await client.post("/", json=_payload("tools/list"), headers={"mcp-session-id": sid})

    data = resp.json()
    assert "error" in data and data["error"]["code"] == -32603
    assert "admin_tool" not in resp.text


# --- Finding 3: response cap uses the response limit + is enforced incrementally ---


async def test_regression_large_response_allowed_under_response_cap() -> None:
    """A ~200KB legitimate tool result must pass with DEFAULT caps — before the
    fix the response reused the 64KB request-sized _max_body_bytes and was rejected."""
    big = "x" * 200_000

    async def _handler(request: Request) -> Response:
        payload = json.loads(await request.body())
        if payload.get("method") == "tools/call":
            return JSONResponse(
                {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"data": big}}
            )
        return JSONResponse({"jsonrpc": "2.0", "id": payload.get("id"), "result": {}})

    inner = Starlette(routes=[Route("/{path:path}", _handler, methods=["POST"])])
    app = ArmorMiddleware(inner, CoSAIGuard([SessionEngine()]))  # default caps

    async with _client(app) as client:
        init = await client.post("/", json=_payload("initialize"))
        sid = init.headers["mcp-session-id"]
        resp = await client.post(
            "/",
            json=_payload("tools/call", {"name": "t", "arguments": {}}),
            headers={"mcp-session-id": sid},
        )

    assert resp.status_code == 200
    assert resp.json()["result"]["data"] == big


async def test_regression_oversized_response_rejected() -> None:
    """A response beyond max_response_bytes fails closed (incremental cap)."""
    big = "x" * 50_000

    async def _handler(request: Request) -> Response:
        payload = json.loads(await request.body())
        if payload.get("method") == "tools/call":
            return JSONResponse(
                {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"data": big}}
            )
        return JSONResponse({"jsonrpc": "2.0", "id": payload.get("id"), "result": {}})

    inner = Starlette(routes=[Route("/{path:path}", _handler, methods=["POST"])])
    app = ArmorMiddleware(inner, CoSAIGuard([SessionEngine()]), max_response_bytes=2_000)

    async with _client(app) as client:
        init = await client.post("/", json=_payload("initialize"))
        sid = init.headers["mcp-session-id"]
        resp = await client.post(
            "/",
            json=_payload("tools/call", {"name": "t", "arguments": {}}),
            headers={"mcp-session-id": sid},
        )

    data = resp.json()
    assert "error" in data and data["error"]["code"] == -32603


# --- Finding 4: _session_budgets is LRU-bounded (no mint-and-abandon leak) ---


def test_regression_session_budgets_lru_bounded() -> None:
    from mcp_armor.context import CoSAIContext
    from mcp_armor.engines.resources import ResourceEngine

    eng = ResourceEngine()
    eng._max_budget_entries = 10
    for i in range(100):
        eng._save_budget(f"s{i}", CoSAIContext.new(f"s{i}").budget)
    assert len(eng._session_budgets) <= 10, "budget ledger grew unbounded"
    assert "s99" in eng._session_budgets  # most-recent retained (LRU)
    assert "s0" not in eng._session_budgets  # oldest evicted
