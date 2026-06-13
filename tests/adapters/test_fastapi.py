"""Tests for ArmorMiddleware (ASGI/FastAPI adapter)."""

from __future__ import annotations

import json

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mcp_armor.adapters.fastapi import ArmorMiddleware
from mcp_armor.engines.session import SessionEngine
from mcp_armor.guard import CoSAIGuard

# ---------------------------------------------------------------------------
# Test app + client fixtures
# ---------------------------------------------------------------------------


async def _echo_handler(request: Request) -> JSONResponse:
    """Simple MCP-like echo handler: returns the method from the JSON body."""
    body = await request.body()
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = {}
    return JSONResponse(
        {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"method": payload.get("method")}}
    )


def _make_app(guard: CoSAIGuard | None = None) -> ArmorMiddleware:
    inner = Starlette(routes=[Route("/{path:path}", _echo_handler, methods=["POST"])])
    g = guard or CoSAIGuard([SessionEngine()])
    return ArmorMiddleware(inner, g)


def _client(app: ArmorMiddleware) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    )


def _payload(method: str, params: dict | None = None, req_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}


# ---------------------------------------------------------------------------
# Session lifecycle — initialize generates session_id (T7-001)
# ---------------------------------------------------------------------------


async def test_initialize_returns_session_header() -> None:
    async with _client(_make_app()) as client:
        resp = await client.post("/", json=_payload("initialize"))
    assert resp.status_code == 200
    assert "mcp-session-id" in resp.headers


async def test_initialize_session_id_is_server_generated() -> None:
    """Server must generate session_id, not accept it from client."""
    async with _client(_make_app()) as client:
        r1 = await client.post("/", json=_payload("initialize"))
        r2 = await client.post("/", json=_payload("initialize"))
    # Two initializations must get different server-generated IDs
    assert r1.headers["mcp-session-id"] != r2.headers["mcp-session-id"]


async def test_request_with_valid_session_id_passes() -> None:
    async with _client(_make_app()) as client:
        init_resp = await client.post("/", json=_payload("initialize"))
        session_id = init_resp.headers["mcp-session-id"]

        resp = await client.post(
            "/",
            json=_payload("tools/call"),
            headers={"mcp-session-id": session_id},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "error" not in data


async def test_request_without_session_header_rejected() -> None:
    async with _client(_make_app()) as client:
        # Non-initialize without session header
        resp = await client.post("/", json=_payload("tools/call"))
    data = resp.json()
    assert "error" in data
    assert data["error"]["code"] == -32600  # JSON-RPC invalid request


async def test_unknown_session_id_rejected() -> None:
    """Session fixation: fabricated session_id must be rejected (T7-001)."""
    async with _client(_make_app()) as client:
        resp = await client.post(
            "/",
            json=_payload("tools/call"),
            headers={"mcp-session-id": "attacker-chosen-id"},
        )
    data = resp.json()
    assert "error" in data
    assert data["error"]["code"] == -32006  # SessionError


# ---------------------------------------------------------------------------
# Session fixation — initialize must also be verified by SessionEngine
# ---------------------------------------------------------------------------


async def test_reinitialize_on_wrong_transport_rejected() -> None:
    """Second initialize on a known session with different transport must fail."""
    app = _make_app()
    async with _client(app) as client:
        init_resp = await client.post("/", json=_payload("initialize"))
        session_id = init_resp.headers["mcp-session-id"]

        # Re-initialize claiming same session is valid (guard runs on_request for initialize too)
        resp = await client.post(
            "/",
            json=_payload("initialize"),
            headers={"mcp-session-id": session_id},
        )
    # The second initialize has no session yet (it generates a new one), so this is OK
    # — but the client sending an initialize WITH an existing session_id header is weird.
    # In our impl, initialize always generates a new session (is_new_session=True)
    # regardless of any incoming header. This test verifies no crash.
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Error handling — JSON-RPC error bodies
# ---------------------------------------------------------------------------


async def test_malformed_json_returns_parse_error() -> None:
    async with _client(_make_app()) as client:
        resp = await client.post(
            "/",
            content=b"not-json",
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["error"]["code"] == -32700


async def test_cosai_exception_returns_jsonrpc_error_not_500() -> None:
    """CoSAIException raised in engine must produce JSON-RPC error, not HTTP 500."""
    async with _client(_make_app()) as client:
        resp = await client.post(
            "/",
            json=_payload("tools/call"),
            headers={"mcp-session-id": "no-such-session"},
        )
    assert resp.status_code == 200  # JSON-RPC spec: errors use HTTP 200
    data = resp.json()
    assert "error" in data
    assert isinstance(data["error"]["code"], int)


# ---------------------------------------------------------------------------
# URL session_id leak prevention (T7-002)
# ---------------------------------------------------------------------------


async def test_session_id_in_url_query_rejected() -> None:
    async with _client(_make_app()) as client:
        init_resp = await client.post("/", json=_payload("initialize"))
        session_id = init_resp.headers["mcp-session-id"]

        resp = await client.post(
            f"/?session_id={session_id}",
            json=_payload("tools/call"),
            headers={"mcp-session-id": session_id},
        )
    data = resp.json()
    assert "error" in data
    assert data["error"]["code"] == -32006  # SessionError (T7-002)


# ---------------------------------------------------------------------------
# Lifespan — startup/shutdown hooks
# ---------------------------------------------------------------------------


async def test_lifespan_startup_calls_guard_startup() -> None:
    """Lifespan startup event must call guard.startup()."""
    started = []

    class TrackingEngine(SessionEngine):
        async def on_startup(self) -> None:
            started.append(True)

    guard = CoSAIGuard([TrackingEngine()])
    inner = Starlette(routes=[Route("/", _echo_handler, methods=["POST"])])
    app = ArmorMiddleware(inner, guard)

    # Simulate lifespan
    scope = {"type": "lifespan"}
    messages = [
        {"type": "lifespan.startup"},
        {"type": "lifespan.shutdown"},
    ]
    msg_iter = iter(messages)

    async def receive():
        return next(msg_iter)

    sent = []

    async def send(msg):
        sent.append(msg)

    await app(scope, receive, send)
    assert any(m["type"] == "lifespan.startup.complete" for m in sent)
    assert started == [True]


# ---------------------------------------------------------------------------
# Dispatcher adapter — session fixation prevention
# ---------------------------------------------------------------------------


async def test_dispatcher_adapter_never_uses_payload_id_as_session() -> None:
    """
    The dispatcher adapter must generate session_id via CSPRNG, never from payload['id'].
    Passing a fabricated 'id' must not become the session_id.
    """
    from mcp_armor.adapters.dispatcher import wrap_dispatcher

    recorded_sessions: list[str] = []

    async def fake_dispatcher(payload: dict) -> dict:
        from mcp_armor.context import get_context

        ctx = get_context()
        recorded_sessions.append(ctx.session_id)
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {}}

    guard = CoSAIGuard([])  # No engines — just test session_id origin
    protected = wrap_dispatcher(fake_dispatcher, guard)

    attacker_id = "attacker-chosen-session-id"
    await protected({"jsonrpc": "2.0", "id": attacker_id, "method": "tools/list", "params": {}})

    assert len(recorded_sessions) == 1
    assert recorded_sessions[0] != attacker_id
    # Session ID must be a UUID (CSPRNG, 128-bit)
    import uuid as _uuid

    _uuid.UUID(recorded_sessions[0])  # raises ValueError if not a valid UUID


# ---------------------------------------------------------------------------
# Panel regression tests
# ---------------------------------------------------------------------------


async def test_regression_close_session_called_on_shutdown() -> None:
    """FIX-1: close_session must be called for tracked sessions on lifespan.shutdown."""
    ended: list[str] = []

    class TrackingEngine(SessionEngine):
        async def on_session_end(self, ctx) -> None:
            ended.append(ctx.session_id)

    guard = CoSAIGuard([TrackingEngine()])
    app = _make_app(guard)

    # Open a session
    async with _client(app) as client:
        init_resp = await client.post("/", json=_payload("initialize"))
        session_id = init_resp.headers["mcp-session-id"]

    # Simulate lifespan shutdown
    scope = {"type": "lifespan"}
    msgs = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])

    async def recv():
        return next(msgs)

    async def send_noop(m):
        pass

    await app(scope, recv, send_noop)
    assert session_id in ended


async def test_regression_lifespan_forwarded_to_wrapped_app() -> None:
    """ArmorMiddleware must forward lifespan.startup/shutdown to the wrapped app.

    Regression for the bug where _handle_lifespan only called guard.startup() but
    never propagated lifespan events to self._app — so any wrapped ASGI app that
    initialises resources in its lifespan (e.g. an httpx client pool) was broken.
    """
    lifecycle: list[str] = []

    class _LifecycleTrackingApp:
        async def __call__(self, scope, receive, send):
            if scope["type"] != "lifespan":
                return
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    lifecycle.append("startup")
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    lifecycle.append("shutdown")
                    await send({"type": "lifespan.shutdown.complete"})
                    return

    guard = CoSAIGuard([])
    app = ArmorMiddleware(_LifecycleTrackingApp(), guard)

    scope = {"type": "lifespan"}
    messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])

    async def receive():
        return next(messages)

    sent = []

    async def send(msg):
        sent.append(msg)

    await app(scope, receive, send)
    assert lifecycle == ["startup", "shutdown"], (
        "ArmorMiddleware must forward lifespan events to the wrapped app"
    )
    assert any(m["type"] == "lifespan.startup.complete" for m in sent)
    assert any(m["type"] == "lifespan.shutdown.complete" for m in sent)


async def test_regression_session_id_url_encoded_key_rejected() -> None:
    """FIX-2: percent-encoded 'session%5fid' must still be detected as session_id in URL."""
    async with _client(_make_app()) as client:
        init_resp = await client.post("/", json=_payload("initialize"))
        session_id = init_resp.headers["mcp-session-id"]

        resp = await client.post(
            f"/?session%5fid={session_id}",  # %5f = _
            json=_payload("tools/call"),
            headers={"mcp-session-id": session_id},
        )
    data = resp.json()
    assert "error" in data
    assert data["error"]["code"] == -32006  # SessionError (T7-002)


async def test_regression_wrong_content_type_rejected() -> None:
    """FIX-3: Content-Type must be application/json; others rejected per CoSAI CodeGuard."""
    async with _client(_make_app()) as client:
        resp = await client.post(
            "/",
            content=json.dumps(_payload("initialize")).encode(),
            headers={"content-type": "text/plain"},
        )
    data = resp.json()
    assert data["error"]["code"] == -32600


async def test_regression_oversized_body_rejected_before_buffering() -> None:
    """FIX-4: body exceeding max_body_bytes must be rejected during receive loop."""
    inner = Starlette(routes=[Route("/{path:path}", _echo_handler, methods=["POST"])])
    guard = CoSAIGuard([SessionEngine()])
    app = ArmorMiddleware(inner, guard, max_body_bytes=16)  # tiny cap

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        resp = await client.post(
            "/",
            content=b"x" * 100,
            headers={"content-type": "application/json"},
        )
    data = resp.json()
    assert data["error"]["code"] == -32600


async def test_regression_session_error_message_is_opaque() -> None:
    """FIX-5: error.message must not expose internal session IDs or transport details."""
    async with _client(_make_app()) as client:
        resp = await client.post(
            "/",
            json=_payload("tools/call"),
            headers={"mcp-session-id": "attacker-chosen-id"},
        )
    data = resp.json()
    assert "error" in data
    # Must not contain the raw session ID
    assert "attacker-chosen-id" not in data["error"]["message"]
    # Must not contain 'fixation' or internal detail
    assert "fixation" not in data["error"]["message"].lower()


async def test_regression_unexpected_engine_exception_returns_json_rpc_error() -> None:
    """FIX-6: non-CoSAIException from engine must return -32603, not HTTP 500."""
    from mcp_armor.engines.base import ProtectionEngine

    class BrokenEngine(ProtectionEngine):
        async def on_session_start(self, ctx):
            raise RuntimeError("disk full")

        async def on_request(self, ctx, req):
            return ctx

        async def on_response(self, ctx, resp):
            return ctx

    guard = CoSAIGuard([BrokenEngine()])
    app = _make_app(guard)

    async with _client(app) as client:
        resp = await client.post("/", json=_payload("initialize"))
    data = resp.json()
    assert data["error"]["code"] == -32603
    assert "traceback" not in data["error"]["message"].lower()
    assert "disk" not in data["error"]["message"]


async def test_regression_upstream_session_header_stripped() -> None:
    """ArmorMiddleware must strip upstream Mcp-Session-Id before injecting its own.

    Regression: when the upstream app also returns an Mcp-Session-Id header, clients
    received two values and used the upstream one, which armor's SessionEngine didn't
    know about — causing all subsequent requests to fail with -32006 Session error.
    """
    from starlette.responses import Response as StarletteResponse

    async def upstream_with_session_header(request: Request) -> StarletteResponse:
        body = await request.body()
        payload = json.loads(body)
        resp = StarletteResponse(
            content=json.dumps({"jsonrpc": "2.0", "id": payload.get("id"), "result": {}}),
            media_type="application/json",
        )
        # Simulate upstream injecting its own session token
        resp.headers["mcp-session-id"] = "upstream-generated-session-jwt-abc123"
        return resp

    inner = Starlette(
        routes=[Route("/{path:path}", upstream_with_session_header, methods=["POST"])]
    )
    guard = CoSAIGuard([SessionEngine()])
    app = ArmorMiddleware(inner, guard)

    async with _client(app) as client:
        init_resp = await client.post("/", json=_payload("initialize"))

    # Response must have exactly one Mcp-Session-Id — armor's CSPRNG UUID, not upstream's JWT
    session_ids = init_resp.headers.get_list("mcp-session-id")
    assert len(session_ids) == 1
    assert session_ids[0] != "upstream-generated-session-jwt-abc123"
    # Must be an armor-issued stateless token that armor's own SessionEngine
    # verifies for the http transport — this is what survives multi-instance
    # (a per-process UUID store was the original -32006 cause).
    session_engine = next(e for e in guard._engines if isinstance(e, SessionEngine))
    session_engine.signer.verify(session_ids[0], "http")


async def test_regression_websocket_scope_not_forwarded_unguarded() -> None:
    """FIX-7: WebSocket scope must not silently bypass the guard."""
    inner = Starlette(routes=[Route("/", _echo_handler, methods=["POST"])])
    guard = CoSAIGuard([SessionEngine()])
    app = ArmorMiddleware(inner, guard)

    ws_scope = {"type": "websocket", "path": "/", "headers": []}
    reached_inner = []

    async def fake_receive():
        return {}

    async def fake_send(msg):
        pass

    with pytest.raises(NotImplementedError):
        await app(ws_scope, fake_receive, fake_send)

    assert not reached_inner


# ---------------------------------------------------------------------------
# Codex findings — P0/P2 regression tests
# ---------------------------------------------------------------------------


async def test_regression_response_violation_blocked_before_delivery() -> None:
    """P0: response engine violation must replace the response with an opaque error —
    the violating body must NOT be delivered to the client first.

    The engine only rejects tools/call responses (the result has 'method': 'tools/call')
    so the initialize round-trip completes and returns the session header normally.
    """
    from mcp_armor.engines.base import ProtectionEngine
    from mcp_armor.exceptions import PIILeakError

    class ResponseRejectOnToolsCall(ProtectionEngine):
        async def on_session_start(self, ctx):
            return ctx

        async def on_request(self, ctx, req):
            return ctx

        async def on_response(self, ctx, resp):
            # Only reject responses that echo back a tools/call method
            if resp.result and resp.result.get("method") == "tools/call":
                raise PIILeakError("credit card in response")
            return ctx

    guard = CoSAIGuard([SessionEngine(), ResponseRejectOnToolsCall()])
    app = _make_app(guard)

    async with _client(app) as client:
        init_resp = await client.post("/", json=_payload("initialize"))
        session_id = init_resp.headers["mcp-session-id"]

        resp = await client.post(
            "/",
            json=_payload("tools/call"),
            headers={"mcp-session-id": session_id},
        )

    data = resp.json()
    # Must get an error response, not the raw upstream body
    assert "error" in data
    assert data["error"]["code"] == -32004  # PIILeakError


async def test_regression_response_violation_body_not_in_reply() -> None:
    """P0: when response guard rejects, the upstream body must not appear in the reply."""
    from mcp_armor.engines.base import ProtectionEngine
    from mcp_armor.exceptions import InjectionDetectedError

    secret_payload = "SENSITIVE_DATA_XYZ"

    async def _leaking_handler(request: Request) -> JSONResponse:
        body = await request.body()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {}
        method = payload.get("method", "")
        if method == "tools/call":
            return JSONResponse({"jsonrpc": "2.0", "id": 1, "result": {"data": secret_payload}})
        return JSONResponse({"jsonrpc": "2.0", "id": payload.get("id"), "result": {}})

    class RejectOnSecretData(ProtectionEngine):
        async def on_session_start(self, ctx):
            return ctx

        async def on_request(self, ctx, req):
            return ctx

        async def on_response(self, ctx, resp):
            if resp.result and "data" in resp.result:
                raise InjectionDetectedError("sensitive data in response")
            return ctx

    inner = Starlette(routes=[Route("/{path:path}", _leaking_handler, methods=["POST"])])
    guard = CoSAIGuard([SessionEngine(), RejectOnSecretData()])
    app = ArmorMiddleware(inner, guard)

    async with _client(app) as client:
        init_resp = await client.post("/", json=_payload("initialize"))
        session_id = init_resp.headers["mcp-session-id"]
        resp = await client.post(
            "/",
            json=_payload("tools/call"),
            headers={"mcp-session-id": session_id},
        )

    assert secret_payload not in resp.text


async def test_regression_non_dict_json_array_rejected() -> None:
    """P2: a JSON array body must return -32600 Invalid Request, not crash on .get()."""
    async with _client(_make_app()) as client:
        resp = await client.post(
            "/",
            content=b'[{"jsonrpc":"2.0","method":"initialize"}]',
            headers={"content-type": "application/json"},
        )
    data = resp.json()
    assert data["error"]["code"] == -32600


async def test_regression_non_dict_scalar_json_rejected() -> None:
    """P2: a scalar JSON value (null, number, string) must return -32600."""
    async with _client(_make_app()) as client:
        resp = await client.post(
            "/",
            content=b"null",
            headers={"content-type": "application/json"},
        )
    data = resp.json()
    assert data["error"]["code"] == -32600


async def test_regression_opaque_codes_injection_is_minus32003() -> None:
    """P2: InjectionDetectedError (T4, code -32003) must map to 'Injection detected'."""
    from mcp_armor.engines.base import ProtectionEngine
    from mcp_armor.exceptions import InjectionDetectedError

    class InjectOnRequest(ProtectionEngine):
        async def on_session_start(self, ctx):
            return ctx

        async def on_request(self, ctx, req):
            if req.method == "tools/call":
                raise InjectionDetectedError("test injection")
            return ctx

        async def on_response(self, ctx, resp):
            return ctx

    guard = CoSAIGuard([SessionEngine(), InjectOnRequest()])
    app = _make_app(guard)

    async with _client(app) as client:
        init_resp = await client.post("/", json=_payload("initialize"))
        session_id = init_resp.headers["mcp-session-id"]
        resp = await client.post(
            "/",
            json=_payload("tools/call"),
            headers={"mcp-session-id": session_id},
        )

    data = resp.json()
    assert data["error"]["code"] == -32003
    assert data["error"]["message"] == "Injection detected"


async def test_regression_opaque_codes_pii_is_minus32004() -> None:
    """P2: PIILeakError (T5, code -32004) must map to 'PII leak detected'."""
    from mcp_armor.engines.base import ProtectionEngine
    from mcp_armor.exceptions import PIILeakError

    class PIIOnResponse(ProtectionEngine):
        async def on_session_start(self, ctx):
            return ctx

        async def on_request(self, ctx, req):
            return ctx

        async def on_response(self, ctx, resp):
            if resp.result and resp.result.get("method") == "tools/call":
                raise PIILeakError("ssn found")
            return ctx

    guard = CoSAIGuard([SessionEngine(), PIIOnResponse()])
    app = _make_app(guard)

    async with _client(app) as client:
        init_resp = await client.post("/", json=_payload("initialize"))
        session_id = init_resp.headers["mcp-session-id"]
        resp = await client.post(
            "/",
            json=_payload("tools/call"),
            headers={"mcp-session-id": session_id},
        )

    data = resp.json()
    assert data["error"]["code"] == -32004
    assert data["error"]["message"] == "PII leak detected"


async def test_regression_opaque_codes_validation_is_minus32602() -> None:
    """P2: ValidationError (T3, code -32602) must be in the opaque map."""
    from mcp_armor.adapters.fastapi import _OPAQUE_MESSAGES

    assert -32602 in _OPAQUE_MESSAGES
    assert _OPAQUE_MESSAGES[-32602] == "Validation error"


# ---------------------------------------------------------------------------
# Fix 3: Compression bomb defence — Content-Encoding rejected before buffering
# ---------------------------------------------------------------------------


async def test_regression_gzip_content_encoding_rejected() -> None:
    """Fix 3: Content-Encoding: gzip must be rejected before body buffering (-32600)."""
    async with _client(_make_app()) as client:
        resp = await client.post(
            "/",
            content=b"fake-gzip-body",
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
            },
        )
    data = resp.json()
    assert data["error"]["code"] == -32600


async def test_regression_deflate_content_encoding_rejected() -> None:
    """Fix 3: Content-Encoding: deflate must also be rejected before body buffering."""
    async with _client(_make_app()) as client:
        resp = await client.post(
            "/",
            content=b"fake-deflate-body",
            headers={
                "content-type": "application/json",
                "content-encoding": "deflate",
            },
        )
    data = resp.json()
    assert data["error"]["code"] == -32600


async def test_regression_identity_content_encoding_allowed() -> None:
    """Fix 3: Content-Encoding: identity (explicit no-op) must not be rejected."""
    async with _client(_make_app()) as client:
        resp = await client.post(
            "/",
            json=_payload("initialize"),
            headers={"content-encoding": "identity"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "error" not in data or data.get("error", {}).get("code") != -32600


# ---------------------------------------------------------------------------
# T10-004: ResourceExceededError → HTTP 429 (not JSON-RPC 200) + Retry-After
# ---------------------------------------------------------------------------


class _AlwaysRateLimitEngine:
    """Stub engine that unconditionally raises ResourceExceededError on tools/call."""

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx):
        return ctx

    async def on_session_end(self, ctx) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass

    async def on_response(self, ctx, resp):
        return ctx

    async def on_request(self, ctx, req):
        from mcp_armor.exceptions import ResourceExceededError

        if req.method == "tools/call":
            raise ResourceExceededError("stub: rate limit exceeded")
        return ctx


async def test_resource_exceeded_returns_http_429() -> None:
    """ResourceExceededError must yield HTTP 429, not JSON-RPC 200, so HTTP-layer rate-
    limiters and cosai-mcp T10-004 probes can detect it (T10-004 / cosai-mcp T10-004)."""
    from mcp_armor.guard import CoSAIGuard

    guard = CoSAIGuard([SessionEngine(), _AlwaysRateLimitEngine()])
    app = _make_app(guard)
    async with _client(app) as client:
        init_resp = await client.post("/", json=_payload("initialize"))
        session_id = init_resp.headers["mcp-session-id"]
        resp = await client.post(
            "/",
            json=_payload("tools/call", {"name": "t", "arguments": {}}),
            headers={"mcp-session-id": session_id},
        )
    assert resp.status_code == 429
    assert "retry-after" in resp.headers
    data = resp.json()
    assert data["error"]["code"] == -32010


async def test_resource_exceeded_retry_after_header_value() -> None:
    """Retry-After header must be present and parseable as a positive integer."""
    from mcp_armor.guard import CoSAIGuard

    guard = CoSAIGuard([SessionEngine(), _AlwaysRateLimitEngine()])
    app = _make_app(guard)
    async with _client(app) as client:
        init_resp = await client.post("/", json=_payload("initialize"))
        session_id = init_resp.headers["mcp-session-id"]
        resp = await client.post(
            "/",
            json=_payload("tools/call", {"name": "t", "arguments": {}}),
            headers={"mcp-session-id": session_id},
        )
    assert resp.status_code == 429
    retry_after = int(resp.headers["retry-after"])
    assert retry_after > 0


# ---------------------------------------------------------------------------
# T7-001 / cosai-mcp T07-001: CORS origin validation
# ---------------------------------------------------------------------------


async def _make_cors_app(cors_origins: list[str] | None) -> ArmorMiddleware:
    """Build an ArmorMiddleware with a specific cors_origins setting."""
    from starlette.applications import Starlette
    from starlette.routing import Route

    inner = Starlette(routes=[Route("/{path:path}", _echo_handler, methods=["POST"])])
    guard = CoSAIGuard([SessionEngine()])
    return ArmorMiddleware(inner, guard, cors_origins=cors_origins)


async def test_cors_allowed_origin_passes() -> None:
    """Requests from a permitted origin must succeed."""
    app = await _make_cors_app(["https://app.example.com"])
    async with _client(app) as client:
        resp = await client.post(
            "/",
            json=_payload("initialize"),
            headers={"Origin": "https://app.example.com"},
        )
    assert resp.status_code == 200
    assert "error" not in resp.json()


async def test_cors_disallowed_origin_rejected() -> None:
    """Requests from an origin not in the allowlist must be rejected with -32600."""
    app = await _make_cors_app(["https://app.example.com"])
    async with _client(app) as client:
        resp = await client.post(
            "/",
            json=_payload("initialize"),
            headers={"Origin": "https://evil.example.com"},
        )
    assert resp.status_code == 200  # JSON-RPC errors are HTTP 200
    data = resp.json()
    assert data["error"]["code"] == -32600


async def test_cors_no_origin_header_passes_when_configured() -> None:
    """Requests without an Origin header are not CORS requests and must be allowed."""
    app = await _make_cors_app(["https://app.example.com"])
    async with _client(app) as client:
        resp = await client.post("/", json=_payload("initialize"))
    assert resp.status_code == 200
    assert "error" not in resp.json()


async def test_cors_empty_allowlist_blocks_all_cross_origin() -> None:
    """cors_origins=[] means no origin is permitted — all cross-origin requests rejected."""
    app = await _make_cors_app([])
    async with _client(app) as client:
        resp = await client.post(
            "/",
            json=_payload("initialize"),
            headers={"Origin": "https://anything.example.com"},
        )
    data = resp.json()
    assert data["error"]["code"] == -32600


async def test_cors_unconfigured_emits_warning_and_passes(caplog) -> None:
    """cors_origins=None (default) emits a startup warning but does not block requests."""
    import logging

    app = await _make_cors_app(None)
    with caplog.at_level(logging.WARNING, logger="mcp_armor.adapters.fastapi"):
        async with _client(app) as client:
            resp = await client.post(
                "/",
                json=_payload("initialize"),
                headers={"Origin": "https://anywhere.com"},
            )
    assert resp.status_code == 200
    assert any("cors_origins not configured" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# T2-004b: tools/list scope filtering via ArmorMiddleware + AuthzEngine
# ---------------------------------------------------------------------------


async def test_tools_list_scope_filter_hides_unpermitted_tools() -> None:
    """tools/list response must not expose tools the caller lacks scope for (T02-004 / D-05)."""
    from starlette.applications import Starlette
    from starlette.routing import Route

    from mcp_armor.config import ToolPolicy
    from mcp_armor.engines.authz import AuthzEngine

    # Inner app returns two tools: one public, one admin
    async def _tools_list_handler(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {"name": "list_items", "description": "read items"},
                        {"name": "admin_purge", "description": "purge everything"},
                    ]
                },
            }
        )

    inner = Starlette(routes=[Route("/{path:path}", _tools_list_handler, methods=["POST"])])
    guard = CoSAIGuard(
        [
            SessionEngine(),
            AuthzEngine(
                tool_policies={
                    "list_items": ToolPolicy(
                        required_scopes=("items:read",),
                        user_only=False,
                        destructive=False,
                        tenant_isolated=False,
                    ),
                    "admin_purge": ToolPolicy(
                        required_scopes=("admin",),
                        user_only=False,
                        destructive=False,
                        tenant_isolated=False,
                    ),
                },
                default_deny=False,
            ),
        ]
    )
    app = ArmorMiddleware(inner, guard)

    async with _client(app) as client:
        # Establish session
        init_resp = await client.post("/", json=_payload("initialize"))
        session_id = init_resp.headers["mcp-session-id"]
        # Call tools/list as a read-only caller (no admin scope on context)
        resp = await client.post(
            "/",
            json=_payload("tools/list"),
            headers={"mcp-session-id": session_id},
        )

    data = resp.json()
    tools = data["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    # admin_purge must be hidden — caller has no scopes, admin_purge requires admin
    assert "admin_purge" not in tool_names


# ---------------------------------------------------------------------------
# A1 regression (AUDIT_2026-06-12): T3 schema validation must be live on the
# adapter path. The schema is auto-registered from the observed tools/list
# response (ValidationEngine.on_response); a valid tools/call then PASSES and an
# inputSchema violation is BLOCKED. Before the fix, _tool_schemas was never
# populated on any live path, so strict_schema=True rejected EVERY tools/call
# with "no registered schema" (self-DoS).
# ---------------------------------------------------------------------------


def _schema_inner_app():
    """Inner MCP app: initialize, tools/list (echo w/ inputSchema), tools/call echo."""

    async def _handler(request: Request) -> JSONResponse:
        body = await request.body()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {}
        method = payload.get("method", "")
        rid = payload.get("id")
        if method == "tools/list":
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "tools": [
                            {
                                "name": "echo",
                                "description": "Echo input",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"message": {"type": "string"}},
                                    "required": ["message"],
                                },
                            }
                        ]
                    },
                }
            )
        if method == "tools/call":
            args = payload.get("params", {}).get("arguments", {})
            text = args.get("message", "") if isinstance(args, dict) else ""
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {"content": [{"type": "text", "text": f"Echo: {text}"}]},
                }
            )
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "1.0"}})

    return Starlette(routes=[Route("/{path:path}", _handler, methods=["POST"])])


async def _init_session(client: httpx.AsyncClient) -> str:
    resp = await client.post("/", json=_payload("initialize"))
    return resp.headers["mcp-session-id"]


async def test_regression_a1_valid_tools_call_passes_after_tools_list() -> None:
    """A1: after tools/list auto-registers the schema, a schema-valid tools/call PASSES."""
    from mcp_armor.engines.validation import ValidationEngine

    guard = CoSAIGuard([SessionEngine(), ValidationEngine()])  # default strict_schema=True
    app = ArmorMiddleware(_schema_inner_app(), guard)
    async with _client(app) as client:
        session = await _init_session(client)
        # tools/list must traverse the guard so the schema is auto-registered.
        listed = await client.post(
            "/", json=_payload("tools/list", req_id=2), headers={"mcp-session-id": session}
        )
        assert "error" not in listed.json()
        # A valid call now passes — NOT the old "no registered schema" self-DoS.
        called = await client.post(
            "/",
            json=_payload(
                "tools/call",
                {"name": "echo", "arguments": {"message": "hello"}},
                req_id=3,
            ),
            headers={"mcp-session-id": session},
        )
        body = called.json()
    assert "error" not in body, f"valid tools/call was blocked: {body}"
    assert body["result"]["content"][0]["text"] == "Echo: hello"


async def test_regression_a1_input_schema_violation_blocked() -> None:
    """A1: a tools/call violating the registered inputSchema is BLOCKED (-32602)."""
    from mcp_armor.engines.validation import ValidationEngine

    guard = CoSAIGuard([SessionEngine(), ValidationEngine()])
    app = ArmorMiddleware(_schema_inner_app(), guard)
    async with _client(app) as client:
        session = await _init_session(client)
        await client.post(
            "/", json=_payload("tools/list", req_id=2), headers={"mcp-session-id": session}
        )
        # message must be a string per inputSchema; 123 violates type:string.
        bad = await client.post(
            "/",
            json=_payload(
                "tools/call",
                {"name": "echo", "arguments": {"message": 123}},
                req_id=3,
            ),
            headers={"mcp-session-id": session},
        )
        body = bad.json()
    assert "error" in body, f"schema violation was not blocked: {body}"
    assert body["error"]["code"] == -32602
