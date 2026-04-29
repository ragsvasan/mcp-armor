"""Custom engine example — extend mcp-armor with a bespoke engine."""

from mcp_armor import CoSAIGuard, CoSAIContext
from mcp_armor.adapters.dispatcher import wrap_dispatcher
from mcp_armor.types import MCPRequest, MCPResponse
from mcp_armor.exceptions import AuthorizationError


class TenantRateLimitEngine:
    """
    Custom engine: enforces a per-tenant call rate limit.

    Each tenant gets at most `max_calls` tool invocations per session.
    This augments the built-in T10 ResourceEngine (which is per-session)
    with tenant-aware accounting.
    """

    def __init__(self, max_calls: int = 10) -> None:
        self._max = max_calls
        self._counts: dict[str, int] = {}

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        if req.method != "tools/call":
            return ctx
        tenant = ctx.tenant_id or "anonymous"
        count = self._counts.get(tenant, 0)
        if count >= self._max:
            raise AuthorizationError(
                f"Tenant '{tenant}' has exceeded the rate limit of {self._max} calls"
            )
        self._counts[tenant] = count + 1
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        self._counts.clear()


# Build a guard with the custom engine alongside the built-ins
guard = CoSAIGuard([
    TenantRateLimitEngine(max_calls=20),
])


async def my_dispatcher(payload: dict) -> dict:
    """Simple dispatcher that handles tools/call."""
    method = payload.get("method", "")
    if method == "tools/call":
        name = payload.get("params", {}).get("name", "")
        args = payload.get("params", {}).get("arguments", {})
        return {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": {"content": [{"type": "text", "text": f"Tool {name} called with {args}"}]},
        }
    return {"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": -32601, "message": "not found"}}


protected_dispatcher = wrap_dispatcher(my_dispatcher, guard)
