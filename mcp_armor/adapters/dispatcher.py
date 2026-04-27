"""Raw JSON-RPC dispatcher adapter — wraps any callable dispatcher."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Callable, Awaitable

if TYPE_CHECKING:
    from ..guard import CoSAIGuard

Dispatcher = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


def wrap_dispatcher(dispatcher: Dispatcher, guard: "CoSAIGuard") -> Dispatcher:
    """
    Wrap a raw async JSON-RPC dispatcher with mcp-armor protection.

    The dispatcher receives a parsed dict and returns a parsed dict.
    This is the lowest-level integration point — use it when you have
    a custom transport or dispatcher that doesn't fit FastMCP/FastAPI.

    Usage:
        protected = wrap_dispatcher(my_dispatcher, guard)
        response = await protected({"method": "tools/call", "params": {...}})
    """

    async def protected(payload: dict[str, Any]) -> dict[str, Any]:
        from ..types import MCPRequest, MCPResponse
        from ..context import CoSAIContext, set_context
        from ..exceptions import CoSAIException, to_jsonrpc_error

        session_id = str(payload.get("id", uuid.uuid4()))
        req = MCPRequest.from_dict(payload, session_id=session_id, headers={})
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
