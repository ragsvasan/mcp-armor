"""FastAPI / ASGI adapter — ASGI middleware wrapping any ASGI app."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import unquote_plus

if TYPE_CHECKING:
    from ..guard import CoSAIGuard

log = logging.getLogger(__name__)

Scope = dict[str, Any]
Receive = Callable
Send = Callable

# MCP spec §3.4 session header (ASGI lowercase)
_SESSION_HEADER = b"mcp-session-id"
_SESSION_HEADER_STR = "mcp-session-id"

# Opaque error messages keyed by JSON-RPC code — internal detail must not reach clients
_OPAQUE_MESSAGES: dict[int, str] = {
    -32001: "Authentication error",
    -32002: "Authorization error",
    -32003: "Validation error",
    -32004: "Injection detected",
    -32005: "PII leak detected",
    -32006: "Session error",
    -32007: "Audit chain error",
    -32008: "Network binding error",
    -32009: "Resource limit exceeded",
    -32010: "Trust boundary violation",
    -32011: "Supply chain error",
    -32012: "Integrity error",
}

# Body size cap enforced during buffering — before deserialization (FIX-4)
_DEFAULT_MAX_BODY = 65_536


class ArmorMiddleware:
    """
    ASGI middleware that applies CoSAIGuard to every MCP JSON-RPC request.

    Session lifecycle (MCP spec §3.4):
    - initialize request  → server generates CSPRNG session_id, calls open_session,
                            injects Mcp-Session-Id into response headers
    - subsequent requests → session_id read from Mcp-Session-Id request header;
                            unknown IDs rejected by SessionEngine (T7-001 fixation)
    - lifespan.shutdown   → all tracked sessions drained via close_session (T7-004)

    Error handling:
    - CoSAIException       → opaque JSON-RPC error body (HTTP 200 per spec); internal
                             detail logged at WARNING, never sent to client (FIX-5)
    - unexpected Exception → -32603 Internal error; full traceback at ERROR log (FIX-6)
    - malformed JSON       → -32700 parse error
    - wrong Content-Type   → -32600 invalid request (CoSAI CodeGuard §Protocol Hygiene)
    - oversized body       → -32600 rejected before buffering completes (FIX-4)
    - WebSocket/SSE scope  → NotImplementedError; guard does not cover these transports (FIX-7)

    Usage (FastAPI):
        app = FastAPI()
        app.add_middleware(ArmorMiddleware, guard=guard)

    Usage (raw ASGI):
        protected_app = ArmorMiddleware(app, guard=guard, max_body_bytes=131_072)
    """

    def __init__(
        self,
        app: Any,
        guard: "CoSAIGuard",
        max_body_bytes: int = _DEFAULT_MAX_BODY,
    ) -> None:
        self._app = app
        self._guard = guard
        self._max_body_bytes = max_body_bytes
        # Tracks open sessions for clean shutdown — session_id → CoSAIContext
        self._active_sessions: dict[str, Any] = {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._handle_lifespan(scope, receive, send)
        elif scope["type"] == "http":
            await self._handle_http(scope, receive, send)
        else:
            # FIX-7: do not silently forward unguarded scope types.
            # ArmorMiddleware only covers HTTP. WebSocket/SSE require their own
            # transport-specific adapter with guard coverage.
            raise NotImplementedError(
                f"ArmorMiddleware does not guard scope type {scope['type']!r}. "
                "Use a transport-specific adapter for WebSocket/SSE transports."
            )

    # -------------------------------------------------------------------------
    # Lifespan
    # -------------------------------------------------------------------------

    async def _handle_lifespan(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Forward lifespan events to the wrapped app via queues so it can initialise
        # its own resources (e.g. httpx connection pool) before we report startup.
        app_receive_q: asyncio.Queue[dict] = asyncio.Queue()
        app_send_q: asyncio.Queue[dict] = asyncio.Queue()

        async def _app_receive() -> dict:
            return await app_receive_q.get()

        async def _app_send(message: dict) -> None:
            await app_send_q.put(message)

        app_task = asyncio.get_event_loop().create_task(
            self._app(scope, _app_receive, _app_send)
        )

        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                # Let the wrapped app start first.
                await app_receive_q.put(message)
                app_msg = await app_send_q.get()
                if app_msg.get("type") == "lifespan.startup.failed":
                    await send(app_msg)
                    return
                # Then initialise the guard.
                try:
                    await self._guard.startup()
                    await send({"type": "lifespan.startup.complete"})
                except Exception as exc:
                    await send({"type": "lifespan.startup.failed", "message": str(exc)})
                    return
            elif message["type"] == "lifespan.shutdown":
                # FIX-1: drain all tracked sessions before shutdown (T7-004)
                for session_id, ctx in list(self._active_sessions.items()):
                    try:
                        await self._guard.close_session(ctx)
                    except Exception as exc:
                        log.error("Error closing session %s on shutdown: %s", session_id, exc)
                self._active_sessions.clear()
                await self._guard.shutdown()
                # Propagate shutdown to the wrapped app.
                await app_receive_q.put(message)
                await app_send_q.get()  # lifespan.shutdown.complete from wrapped app
                await send({"type": "lifespan.shutdown.complete"})
                await app_task
                return

    # -------------------------------------------------------------------------
    # HTTP request/response
    # -------------------------------------------------------------------------

    async def _handle_http(self, scope: Scope, receive: Receive, send: Send) -> None:
        from ..types import MCPRequest, MCPResponse
        from ..context import CoSAIContext, set_context
        from ..exceptions import CoSAIException

        # FIX-4: cap body size during buffering, before deserialization
        body_parts: list[bytes] = []
        accumulated = 0
        more = True
        while more:
            msg = await receive()
            chunk = msg.get("body", b"")
            accumulated += len(chunk)
            if accumulated > self._max_body_bytes:
                await _send_error(send, None, -32600,
                                  f"Payload exceeds {self._max_body_bytes} bytes")
                return
            body_parts.append(chunk)
            more = msg.get("more_body", False)
        raw_body = b"".join(body_parts)

        # Decode headers and query string before Content-Type check
        raw_headers: dict[str, str] = {
            k.decode("latin-1"): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }

        # FIX-3: enforce Content-Type: application/json (CoSAI CodeGuard §Protocol Hygiene)
        if raw_body:
            ct = raw_headers.get("content-type", "").split(";")[0].strip()
            if ct and ct != "application/json":
                await _send_error(send, None, -32600,
                                  "Content-Type must be application/json")
                return

        # Parse JSON
        try:
            payload: dict[str, Any] = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError:
            await _send_error(send, None, -32700, "Parse error: invalid JSON")
            return

        request_id = payload.get("id")

        # FIX-2: URL-decode query string keys/values to prevent percent-encoding bypass (T7-002)
        url_query_params = _parse_qs(scope.get("query_string", b"").decode("latin-1"))

        # Session resolution (MCP spec §3.4)
        method = payload.get("method", "")
        if method == "initialize":
            # Server owns session identity — always CSPRNG-generated (T7-001)
            session_id = str(uuid.uuid4())
            is_new_session = True
        else:
            session_id = raw_headers.get(_SESSION_HEADER_STR, "")
            is_new_session = False
            if not session_id:
                await _send_error(send, request_id, -32600,
                                  "Missing Mcp-Session-Id header")
                return

        ctx = CoSAIContext.new(session_id, transport="http")
        set_context(ctx)

        # FIX-6: catch all exceptions — unexpected errors must not leak tracebacks
        try:
            if is_new_session:
                ctx = await self._guard.open_session(ctx)
                set_context(ctx)
                # FIX-1: track for shutdown drain
                self._active_sessions[session_id] = ctx

            req = MCPRequest.from_dict(
                payload,
                session_id=session_id,
                headers=raw_headers,
                url_query_params=url_query_params,
                transport="http",
            )
            ctx = await self._guard._run_request(ctx, req)
            set_context(ctx)

        except CoSAIException as exc:
            # FIX-5: log full detail internally; send opaque message to client
            log.warning("Guard rejected request [%s]: %s", exc.__class__.__name__, exc)
            client_msg = _OPAQUE_MESSAGES.get(exc.json_rpc_code, "Request rejected")
            await _send_error(send, request_id, exc.json_rpc_code, client_msg)
            return
        except Exception as exc:
            # FIX-6: unexpected engine failure — internal error only
            log.error("Unexpected guard error on request: %s", exc, exc_info=True)
            await _send_error(send, request_id, -32603, "Internal error")
            return

        # Wrap send to inject Mcp-Session-Id header on initialize
        response_body_parts: list[bytes] = []

        async def wrapped_send(message: dict) -> None:
            if message["type"] == "http.response.start" and is_new_session:
                # Strip any upstream Mcp-Session-Id — the upstream server may generate
                # its own session token, but clients must use armor's CSPRNG-generated
                # session_id so the SessionEngine can verify subsequent requests (T7-001).
                headers = [
                    (k, v) for k, v in message.get("headers", [])
                    if k.lower() != _SESSION_HEADER
                ]
                headers.append((_SESSION_HEADER, session_id.encode("ascii")))
                message = {**message, "headers": headers}
            if message["type"] == "http.response.body":
                response_body_parts.append(message.get("body", b""))
            await send(message)

        body_iter = iter([
            {"type": "http.request", "body": raw_body, "more_body": False}
        ])

        async def replay_receive() -> dict:
            try:
                return next(body_iter)
            except StopIteration:
                return {"type": "http.disconnect"}

        await self._app(scope, replay_receive, wrapped_send)

        # Response-phase guard (finding logged; response already committed)
        resp_raw = b"".join(response_body_parts)
        try:
            resp_dict = json.loads(resp_raw) if resp_raw else {}
        except json.JSONDecodeError:
            resp_dict = {}
        resp = MCPResponse.from_dict(resp_dict)
        try:
            await self._guard._run_response(ctx, resp)
        except CoSAIException as exc:
            log.warning("Guard response violation [%s]: %s", exc.__class__.__name__, exc)
        except Exception as exc:
            log.error("Unexpected guard error on response: %s", exc, exc_info=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_qs(query_string: str) -> dict[str, str]:
    """Parse a URL query string with percent-decoding (FIX-2: prevents T7-002 bypass)."""
    if not query_string:
        return {}
    result: dict[str, str] = {}
    for part in query_string.split("&"):
        if "=" in part:
            k, _, v = part.partition("=")
            result[unquote_plus(k)] = unquote_plus(v)
        elif part:
            result[unquote_plus(part)] = ""
    return result


async def _send_error(send: Send, request_id: Any, code: int, message: str) -> None:
    """Send a JSON-RPC 2.0 error response (HTTP 200 per JSON-RPC spec)."""
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }).encode()
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body, "more_body": False})
