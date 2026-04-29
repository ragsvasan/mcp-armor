"""FastMCP adapter — wraps a FastMCP app with CoSAIGuard protection."""

from __future__ import annotations

import html
import logging
import uuid
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..guard import CoSAIGuard

log = logging.getLogger(__name__)


def wrap_fastmcp(app: Any, guard: "CoSAIGuard") -> Any:
    """
    Wrap a FastMCP application with mcp-armor protection.

    Hooks into FastMCP's tool dispatch by wrapping the underlying ASGI app
    with ArmorMiddleware. FastMCP exposes an ASGI-compatible app via
    `app.http_app()` (FastMCP ≥ 2.x); ArmorMiddleware is then composed on top.

    For each tool call:
    1. ArmorMiddleware runs the full guard chain (auth → session → authz → … → audit)
    2. The validated request is forwarded to FastMCP's own dispatcher
    3. The response is scanned by the response-phase engines

    Session lifecycle follows MCP spec §3.4:
    - initialize → server generates Mcp-Session-Id, injects into response headers
    - subsequent calls → session validated against SessionEngine store

    Usage:
        from fastmcp import FastMCP
        from mcp_armor import CoSAIGuard
        from mcp_armor.adapters.fastmcp import wrap_fastmcp

        app = FastMCP("my-server")
        guard = CoSAIGuard.from_config("cosai.yaml")
        protected = wrap_fastmcp(app, guard)

        # Serve with uvicorn:
        uvicorn.run(protected, host="127.0.0.1", port=8000)

    Requires: pip install mcp-armor[fastmcp]
    """
    try:
        import fastmcp
    except ImportError as exc:
        raise ImportError(
            "fastmcp is required for this adapter: pip install mcp-armor[fastmcp]"
        ) from exc

    # FIX-3: require a real FastMCP instance — reject duck-typed lookalikes
    if not isinstance(app, fastmcp.FastMCP):
        raise TypeError(
            f"wrap_fastmcp requires a fastmcp.FastMCP instance, got {type(app)!r}"
        )

    from .fastapi import ArmorMiddleware

    # FastMCP ≥ 2.x exposes the underlying ASGI app via http_app()
    # FastMCP 1.x exposes it via the app attribute
    if hasattr(app, "http_app"):
        asgi_app = app.http_app()
    elif hasattr(app, "app"):
        asgi_app = app.app
    else:
        raise TypeError(
            f"Cannot extract ASGI app from FastMCP instance of type {type(app)!r}. "
            "Expected 'http_app()' method (FastMCP ≥ 2.x) or 'app' attribute (FastMCP 1.x)."
        )

    return ArmorMiddleware(asgi_app, guard)


class _GuardedToolDispatcher:
    """
    Low-level hook for FastMCP tool dispatch (per-tool alternative to wrap_fastmcp).

    Wraps individual tool functions with guard protection at the function level.
    Intended for use with @guard.protect() or direct decoration when ASGI-layer
    wrapping is not appropriate (e.g., stdio-only FastMCP servers).

    Each invocation creates its own session (one session per tool call), which
    matches stdio semantics where there is no persistent session concept. For
    HTTP FastMCP servers use wrap_fastmcp() instead — it shares session state
    across multiple tool calls via Mcp-Session-Id headers.

    NOT compatible with simultaneous use of wrap_fastmcp() on the same guard —
    that would create two independent session entries per call.
    """

    def __init__(self, guard: "CoSAIGuard") -> None:
        self._guard = guard

    def hook(self, fn: Any, transport: str = "stdio") -> Any:
        """
        Decorate a FastMCP tool function with guard protection.

        transport: the MCP transport this server uses. Default "stdio" is correct
                   for stdio FastMCP servers. Pass "http" for HTTP-transport servers
                   to allow SessionEngine T7-003 cross-transport checks to work correctly.
        """
        import functools

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            from ..types import MCPRequest, MCPResponse
            from ..context import CoSAIContext, set_context
            from types import MappingProxyType

            # FIX-2: use caller-supplied transport, not hardcoded "stdio"
            session_id = str(uuid.uuid4())
            ctx = CoSAIContext.new(session_id, transport=transport)
            set_context(ctx)

            tool_name = fn.__name__
            req = MCPRequest(
                method="tools/call",
                params=MappingProxyType({"name": tool_name, "arguments": dict(kwargs)}),
                session_id=session_id,
                raw_headers=MappingProxyType({}),
                transport=transport,  # FIX-2
            )

            # FIX-1: guarantee close_session fires regardless of which phase raises.
            # session_opened tracks whether open_session completed so we only close
            # sessions that were actually registered in each engine's store.
            session_opened = False
            try:
                ctx = await self._guard.open_session(ctx)
                session_opened = True
                set_context(ctx)

                ctx = await self._guard._run_request(ctx, req)
                set_context(ctx)

                result = await fn(*args, **kwargs)

                # FIX-5: apply html.escape at ingestion — same path as MCPResponse.from_dict()
                # Prevents dual-encoding bypass against TrustEngine/PIIEngine string patterns.
                escaped_body = html.escape(str(result)[:65536], quote=True)
                resp = MCPResponse(result=None, error=None, raw_body=escaped_body)
                await self._guard._run_response(ctx, resp)

                return result

            finally:
                # FIX-1: always drain the session if it was opened
                if session_opened:
                    try:
                        await self._guard.close_session(ctx)
                    except Exception as exc:
                        log.error("Error closing session %s: %s", session_id, exc)

        return wrapper
