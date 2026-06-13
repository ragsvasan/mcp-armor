"""Raw JSON-RPC dispatcher adapter — wraps any callable dispatcher."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..guard import CoSAIGuard

Dispatcher = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


def wrap_dispatcher(dispatcher: Dispatcher, guard: CoSAIGuard) -> Dispatcher:
    """
    Wrap a raw async JSON-RPC dispatcher with mcp-armor protection.

    The dispatcher receives a parsed dict and returns a parsed dict.
    This is the lowest-level integration point — use it when you have
    a custom transport or dispatcher that doesn't fit FastMCP/FastAPI.

    SCOPE — single-call session only (B3). A fresh signed session id is minted on
    EVERY call (mint_session_id below), so no per-session state accumulates across
    calls on this transport: T6 mid-session manifest drift never has a baseline to
    compare against, and the T10 call/wall-clock budget resets every call and so
    never trips. The response-phase guard runs for side effects (PII/injection
    blocking, audit) but its evolved context is discarded. Use this adapter only
    where each call is genuinely independent; for cross-call T6/T10 enforcement
    use the ASGI ArmorMiddleware (FastAPI/FastMCP) which threads one session id
    across requests via the Mcp-Session-Id header.

    Usage:
        protected = wrap_dispatcher(my_dispatcher, guard)
        response = await protected({"method": "tools/call", "params": {...}})
    """

    async def protected(payload: dict[str, Any]) -> dict[str, Any]:
        from ..context import CoSAIContext, set_context
        from ..exceptions import CoSAIException, to_jsonrpc_error
        from ..types import MCPRequest, MCPResponse

        # Session ID MUST be server-generated. JSON-RPC `id` is for
        # request-response correlation only — never derive session identity from it.
        # Using payload["id"] as session_id would allow session fixation (T7-001).
        # Stateless signed token (transport "rpc") so SessionEngine.verify() accepts it.
        session_id = guard.mint_session_id("rpc")
        req = MCPRequest.from_dict(payload, session_id=session_id, headers={}, transport="rpc")
        ctx = CoSAIContext.new(session_id)
        set_context(ctx)

        try:
            ctx = await guard._run_request(ctx, req)
            set_context(ctx)
            raw_resp = await dispatcher(payload)
            resp = MCPResponse.from_dict(raw_resp)
            await guard._run_response(ctx, resp)
            return raw_resp
        except CoSAIException as exc:
            from ..exceptions import to_jsonrpc_error

            return {"jsonrpc": "2.0", "id": payload.get("id"), "error": to_jsonrpc_error(exc)}

    return protected
