"""Regression tests for the 2026-07-17 egress audit (H1 + fastmcp ContextVar).

H1 — response scan/forward asymmetry: the response-phase engines (T4/T5/T9)
must inspect the exact bytes forwarded to the client. Two historical holes:
  (a) MCPResponse.from_dict scanned only str(dict)[:65536], so PII/secrets
      positioned past 64 KB were forwarded unscanned;
  (b) a non-JSON upstream body made resp_dict={}, the scan saw "{}" (clean),
      and the raw non-JSON bytes were forwarded — a total fail-open.

LOW — the FastMCP _GuardedToolDispatcher.hook set _active_ctx but never reset
it, leaking the tool's ctx to any later tool/task on the same asyncio task.
"""

from __future__ import annotations

import json

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from mcp_armor.adapters.fastapi import ArmorMiddleware
from mcp_armor.engines.protection import ProtectionEngine
from mcp_armor.engines.session import SessionEngine
from mcp_armor.guard import CoSAIGuard


def _client(app: ArmorMiddleware) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    )


def _payload(method: str, params: dict | None = None, req_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}


# ---------------------------------------------------------------------------
# H1 (a): the response scan must cover the FULL body, not str(dict)[:65536]
# ---------------------------------------------------------------------------


async def test_regression_response_scan_covers_full_body() -> None:
    """A PII payload positioned PAST 64 KB in the response must be detected and
    blocked (T5 -32004). Before the fix scan_body was str(dict)[:65536], so the
    SSN beyond the 64 KB boundary was never scanned and was egress'd verbatim."""
    ssn = "123-45-6789"
    # Trailing space gives the SSN regex its leading \b word boundary; the 100 KB
    # of padding guarantees the SSN sits far past the old str(dict)[:65536] cut.
    padding = "A" * 100_000 + " "

    async def _big_pii_handler(request: Request) -> JSONResponse:
        body = await request.body()
        payload = json.loads(body)
        if payload.get("method") == "tools/call":
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": payload.get("id"),
                    "result": {"data": padding + ssn},
                }
            )
        return JSONResponse({"jsonrpc": "2.0", "id": payload.get("id"), "result": {}})

    inner = Starlette(routes=[Route("/{path:path}", _big_pii_handler, methods=["POST"])])
    guard = CoSAIGuard([SessionEngine(), ProtectionEngine(profile="pci")])
    # Large body cap so the response clears the size gate and reaches the scanner
    # — the property under test is scan coverage, not the size cap.
    app = ArmorMiddleware(inner, guard, max_body_bytes=5_000_000)

    async with _client(app) as client:
        init = await client.post("/", json=_payload("initialize"))
        session_id = init.headers["mcp-session-id"]
        resp = await client.post(
            "/",
            json=_payload("tools/call", {"name": "t", "arguments": {}}),
            headers={"mcp-session-id": session_id},
        )

    data = resp.json()
    assert "error" in data, "PII positioned past 64 KB was forwarded unscanned"
    assert data["error"]["code"] == -32004  # PIILeakError (T5)
    # The sensitive value must never appear in what the client receives.
    assert ssn not in resp.text


# ---------------------------------------------------------------------------
# H1 (b): a non-JSON upstream body must fail CLOSED when scanners are active
# ---------------------------------------------------------------------------


async def test_regression_nonjson_response_fails_closed() -> None:
    """With a response-scanning engine active, a non-JSON upstream body must be
    rejected with an opaque error — NOT forwarded. Before the fix a json.loads
    failure set resp_dict={}, the scan saw "{}" (clean), and the raw non-JSON
    bytes (including any secret) were sent straight to the client."""
    secret = "123-45-6789"  # noqa: S105 — deliberate fake SSN fixture, not a credential

    async def _nonjson_handler(request: Request) -> Response:
        body = await request.body()
        payload = json.loads(body)
        if payload.get("method") == "tools/call":
            # Upstream emits a non-JSON body carrying a secret.
            return PlainTextResponse(f"<html>leaked {secret}</html>")
        return JSONResponse({"jsonrpc": "2.0", "id": payload.get("id"), "result": {}})

    inner = Starlette(routes=[Route("/{path:path}", _nonjson_handler, methods=["POST"])])
    guard = CoSAIGuard([SessionEngine(), ProtectionEngine(profile="pci")])
    app = ArmorMiddleware(inner, guard)

    async with _client(app) as client:
        init = await client.post("/", json=_payload("initialize"))
        session_id = init.headers["mcp-session-id"]
        resp = await client.post(
            "/",
            json=_payload("tools/call", {"name": "t", "arguments": {}}),
            headers={"mcp-session-id": session_id},
        )

    data = resp.json()
    assert "error" in data, "non-JSON response was forwarded clean (fail-open)"
    assert data["error"]["code"] == -32603  # opaque Internal error, fail-closed
    assert secret not in resp.text


async def test_regression_nonjson_response_passthrough_without_scanners() -> None:
    """Guard against over-rejection: when NO response-content scanner is active,
    a non-JSON body is still passed through (fail-closed is scoped to configs
    whose egress guarantee the non-JSON body would otherwise defeat)."""

    async def _nonjson_handler(request: Request) -> Response:
        body = await request.body()
        payload = json.loads(body)
        if payload.get("method") == "tools/call":
            return PlainTextResponse("plain text, not json")
        return JSONResponse({"jsonrpc": "2.0", "id": payload.get("id"), "result": {}})

    inner = Starlette(routes=[Route("/{path:path}", _nonjson_handler, methods=["POST"])])
    guard = CoSAIGuard([SessionEngine()])  # no response-content scanner
    app = ArmorMiddleware(inner, guard)

    async with _client(app) as client:
        init = await client.post("/", json=_payload("initialize"))
        session_id = init.headers["mcp-session-id"]
        resp = await client.post(
            "/",
            json=_payload("tools/call", {"name": "t", "arguments": {}}),
            headers={"mcp-session-id": session_id},
        )

    assert resp.status_code == 200
    assert resp.text == "plain text, not json"


# ---------------------------------------------------------------------------
# LOW: FastMCP dispatcher hook must reset the _active_ctx ContextVar
# ---------------------------------------------------------------------------


async def test_regression_fastmcp_contextvar_reset() -> None:
    """_GuardedToolDispatcher.hook must restore _active_ctx to its prior value
    after the tool returns (mirror the ASGI Fix 8). Before the fix the ctx it
    .set() leaked to any later @guard.protect tool / background task on the same
    asyncio task — a scope/tenant bleed in a multi-principal async server."""
    from mcp_armor.adapters.fastmcp import _GuardedToolDispatcher
    from mcp_armor.guard import _active_ctx

    dispatcher = _GuardedToolDispatcher(CoSAIGuard([SessionEngine()]))

    seen_inside: list[bool] = []

    async def my_tool(**kwargs: object) -> str:
        # Proves the hook actually populates the ContextVar during dispatch, so
        # the post-call reset assertion below is meaningful (not vacuously true).
        seen_inside.append(_active_ctx.get() is not None)
        return "ok"

    wrapped = dispatcher.hook(my_tool, transport="http")

    before = _active_ctx.get()
    result = await wrapped()

    assert result == "ok"
    assert seen_inside == [True], "hook did not expose ctx to the tool during dispatch"
    assert _active_ctx.get() is before, "ContextVar leaked — not reset after tool returned"
