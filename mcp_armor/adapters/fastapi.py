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

# Opaque error messages keyed by JSON-RPC code — aligned with CoSAIException subclasses
_OPAQUE_MESSAGES: dict[int, str] = {
    -32001: "Authentication error",         # AuthenticationError (T1)
    -32002: "Authorization error",          # AuthorizationError (T2)
    -32003: "Injection detected",           # InjectionDetectedError (T4)
    -32004: "PII leak detected",            # PIILeakError (T5)
    -32005: "Integrity error",              # IntegrityError (T6)
    -32006: "Session error",                # SessionError (T7)
    -32007: "Trust boundary violation",     # TrustBoundaryViolation (T9)
    -32008: "Network binding error",        # NetworkBindingError (T8)
    -32009: "Audit chain error",            # AuditChainError (T12)
    -32010: "Resource limit exceeded",      # ResourceExceededError (T10)
    -32011: "Supply chain error",           # SupplyChainError (T11)
    -32602: "Validation error",             # ValidationError (T3, standard invalid params)
}

# Body size cap enforced during buffering — before deserialization (FIX-4)
_DEFAULT_MAX_BODY = 65_536

# Sentinel: CORS wildcard — never permitted on an MCP endpoint (T7-001 / cosai-mcp T07-001)
_CORS_WILDCARD = "*"


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
        cors_origins: list[str] | None = None,
    ) -> None:
        self._app = app
        self._guard = guard
        self._max_body_bytes = max_body_bytes
        # CORS allowlist — None means "no CORS validation configured" (emits startup warning).
        # Set to a list of permitted origins to enforce; wildcard ("*") is never permitted.
        self._cors_origins: frozenset[str] | None = (
            frozenset(cors_origins) if cors_origins is not None else None
        )
        if self._cors_origins is None:
            log.warning(
                "ArmorMiddleware: cors_origins not configured — CORS policy is NOT enforced. "
                "Set cors_origins=[] to block all cross-origin requests, or list your "
                "permitted origins. A wildcard on the MCP endpoint allows any web page to "
                "make credentialed requests (T7-001 / cosai-mcp T07-001)."
            )
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

        # Decode headers early — needed before buffering for Content-Encoding and
        # Content-Type checks. Decoding once here avoids a second pass later.
        raw_headers: dict[str, str] = {
            k.decode("latin-1"): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }

        # T7-001 / T07-001: CORS origin validation.
        # If cors_origins is configured, reject requests whose Origin header is not
        # in the allowlist.  A wildcard ACAO on the MCP endpoint lets any web page
        # make credentialed requests on behalf of an authenticated user.
        request_origin = raw_headers.get("origin", "")
        if self._cors_origins is not None and request_origin:
            if request_origin not in self._cors_origins:
                await _send_error(send, None, -32600,
                                  "Origin not in CORS allowlist (T7-001)")
                return

        # Reject compressed bodies before buffering — the pre-parse size cap covers
        # raw bytes only; decompressed content is unbounded (CoSAI CodeGuard
        # §Protocol Hygiene / compression-bomb defence).
        encoding = raw_headers.get("content-encoding", "").strip().lower()
        if encoding and encoding != "identity":
            await _send_error(send, None, -32600, "Content-Encoding is not supported")
            return

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

        # FIX-3: enforce Content-Type: application/json (CoSAI CodeGuard §Protocol Hygiene)
        if raw_body:
            ct = raw_headers.get("content-type", "").split(";")[0].strip()
            if ct and ct != "application/json":
                await _send_error(send, None, -32600,
                                  "Content-Type must be application/json")
                return

        # Parse JSON — reject non-dict shapes (batch arrays, scalars) before .get() calls
        try:
            parsed: Any = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError:
            await _send_error(send, None, -32700, "Parse error: invalid JSON")
            return

        if not isinstance(parsed, dict):
            await _send_error(send, None, -32600,
                              "Invalid Request: expected a JSON object")
            return

        payload: dict[str, Any] = parsed
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
            # FIX-5: log full detail internally; send opaque message to client.
            # T10-004: ResourceExceededError is returned as HTTP 429 (not JSON-RPC 200)
            # so that HTTP-layer rate-limiters (proxies, cosai-mcp T10-004 probe) detect it.
            log.warning("Guard rejected request [%s]: %s", exc.__class__.__name__, exc)
            from ..exceptions import ResourceExceededError
            if isinstance(exc, ResourceExceededError):
                await _send_rate_limited(send, request_id)
                return
            client_msg = _OPAQUE_MESSAGES.get(exc.json_rpc_code, "Request rejected")
            await _send_error(send, request_id, exc.json_rpc_code, client_msg)
            return
        except Exception as exc:
            # FIX-6: unexpected engine failure — internal error only
            log.error("Unexpected guard error on request: %s", exc, exc_info=True)
            await _send_error(send, request_id, -32603, "Internal error")
            return

        # Buffer the entire upstream response before running the response-phase guard.
        # Nothing is sent to the client until all response engines pass — violations
        # replace the response with an opaque JSON-RPC error (P0 fix).
        response_start_msg: dict | None = None
        response_body_parts: list[bytes] = []

        async def buffering_send(message: dict) -> None:
            nonlocal response_start_msg
            if message["type"] == "http.response.start":
                if is_new_session:
                    # Strip any upstream Mcp-Session-Id — clients must use armor's
                    # CSPRNG-generated session_id (T7-001).
                    headers = [
                        (k, v) for k, v in message.get("headers", [])
                        if k.lower() != _SESSION_HEADER
                    ]
                    headers.append((_SESSION_HEADER, session_id.encode("ascii")))
                    message = {**message, "headers": headers}
                response_start_msg = message
            elif message["type"] == "http.response.body":
                response_body_parts.append(message.get("body", b""))
            # Do NOT forward to `send` here — buffer everything until guard passes.

        body_iter = iter([
            {"type": "http.request", "body": raw_body, "more_body": False}
        ])

        async def replay_receive() -> dict:
            try:
                return next(body_iter)
            except StopIteration:
                return {"type": "http.disconnect"}

        await self._app(scope, replay_receive, buffering_send)

        # Run response-phase guard BEFORE committing response to client.
        resp_raw = b"".join(response_body_parts)
        try:
            resp_dict = json.loads(resp_raw) if resp_raw else {}
        except json.JSONDecodeError:
            resp_dict = {}
        resp = MCPResponse.from_dict(resp_dict)
        try:
            ctx = await self._guard._run_response(ctx, resp)
        except CoSAIException as exc:
            log.warning("Guard response violation [%s]: %s", exc.__class__.__name__, exc)
            client_msg = _OPAQUE_MESSAGES.get(exc.json_rpc_code, "Response rejected")
            await _send_error(send, request_id, exc.json_rpc_code, client_msg)
            return
        except Exception as exc:
            log.error("Unexpected guard error on response: %s", exc, exc_info=True)
            await _send_error(send, request_id, -32603, "Internal error")
            return

        # T2-004b / cosai-mcp T02-004: scope-filter the tools/list manifest.
        # A caller must not discover tool names they cannot call.  Re-serialise the
        # filtered manifest and update content-length so the client receives a
        # consistent response.
        if method == "tools/list" and resp_dict:
            tools_result = resp_dict.get("result", {})
            if isinstance(tools_result, dict):
                raw_tools = tools_result.get("tools", [])
                if isinstance(raw_tools, list):
                    tool_names = [
                        t.get("name", "") for t in raw_tools if isinstance(t, dict)
                    ]
                    allowed_names = set(self._guard.filter_tools_list(tool_names, ctx))
                    filtered_tools = [
                        t for t in raw_tools
                        if isinstance(t, dict) and t.get("name") in allowed_names
                    ]
                    if len(filtered_tools) != len(raw_tools):
                        filtered_resp = {
                            **resp_dict,
                            "result": {**tools_result, "tools": filtered_tools},
                        }
                        resp_raw = json.dumps(filtered_resp).encode()
                        # Patch content-length in the already-captured start message.
                        if response_start_msg is not None:
                            patched_headers = [
                                (k, v) for k, v in response_start_msg.get("headers", [])
                                if k.lower() != b"content-length"
                            ]
                            patched_headers.append(
                                (b"content-length", str(len(resp_raw)).encode())
                            )
                            response_start_msg = {
                                **response_start_msg, "headers": patched_headers
                            }

        # Guard passed — replay buffered response to client.
        if response_start_msg is not None:
            await send(response_start_msg)
        await send({"type": "http.response.body", "body": resp_raw, "more_body": False})


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


async def _send_rate_limited(send: Send, request_id: Any) -> None:
    """Send HTTP 429 Too Many Requests for ResourceExceededError (T10-004).

    HTTP 429 is used instead of JSON-RPC 200 so that:
    - HTTP-layer rate-limit proxies (nginx, cloud WAFs) can detect and act on it
    - cosai-mcp T10-004 probe (which checks response.status_code status_in [429, 503]) passes
    - RFC 6585 §4 is honoured: rate limit responses at the HTTP layer, not buried in JSON-RPC
    """
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32010, "message": "Rate limit exceeded — retry after 60 seconds"},
    }).encode()
    await send({
        "type": "http.response.start",
        "status": 429,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"retry-after", b"60"),
        ],
    })
    await send({"type": "http.response.body", "body": body, "more_body": False})
