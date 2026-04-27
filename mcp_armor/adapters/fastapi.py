"""FastAPI / ASGI adapter — ASGI middleware wrapping any ASGI app."""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from ..guard import CoSAIGuard

Scope = dict[str, Any]
Receive = Callable
Send = Callable


class ArmorMiddleware:
    """
    ASGI middleware that applies CoSAIGuard to every MCP JSON-RPC request.

    Usage (FastAPI):
        app = FastAPI()
        app.add_middleware(ArmorMiddleware, guard=guard)

    Usage (raw ASGI):
        protected_app = ArmorMiddleware(app, guard=guard)
    """

    def __init__(self, app: Any, guard: "CoSAIGuard") -> None:
        self._app = app
        self._guard = guard

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        # Read body
        body_parts: list[bytes] = []
        more = True
        while more:
            message = await receive()
            body_parts.append(message.get("body", b""))
            more = message.get("more_body", False)
        raw_body = b"".join(body_parts)

        # Parse JSON-RPC
        try:
            payload = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError:
            payload = {}

        headers = dict(scope.get("headers", []))
        decoded_headers = {k.decode(): v.decode() for k, v in headers.items()}
        session_id = decoded_headers.get("x-mcp-session-id", str(uuid.uuid4()))

        from ..types import MCPRequest, MCPResponse
        from ..context import CoSAIContext, set_context

        req = MCPRequest.from_dict(payload, session_id=session_id, headers=decoded_headers)
        ctx = CoSAIContext.new(session_id)
        set_context(ctx)

        # Run request-phase engines — raises CoSAIException on violation
        ctx = await self._guard._run_request(ctx, req)
        set_context(ctx)

        # Capture response via send wrapper
        response_body: list[bytes] = []
        status_code: list[int] = [200]

        async def capturing_send(message: dict) -> None:
            if message["type"] == "http.response.start":
                status_code[0] = message.get("status", 200)
            elif message["type"] == "http.response.body":
                response_body.append(message.get("body", b""))
            await send(message)

        # Reconstruct receive that replays the body we already consumed
        body_iter = iter([
            {"type": "http.request", "body": raw_body, "more_body": False}
        ])

        async def replay_receive() -> dict:
            try:
                return next(body_iter)
            except StopIteration:
                return {"type": "http.disconnect"}

        await self._app(scope, replay_receive, capturing_send)

        # Run response-phase engines
        resp_raw = b"".join(response_body)
        try:
            resp_dict = json.loads(resp_raw) if resp_raw else {}
        except json.JSONDecodeError:
            resp_dict = {}

        resp = MCPResponse.from_dict(resp_dict)
        await self._guard._run_response(ctx, resp)
