"""ProtectionEngine protocol — the interface every engine must implement."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..context import CoSAIContext
from ..types import MCPRequest, MCPResponse


@runtime_checkable
class ProtectionEngine(Protocol):
    """
    Lifecycle hooks called by CoSAIGuard for every request.

    Engines are stateless relative to a single request — all state flows
    through CoSAIContext. Engines may raise CoSAIException subclasses to
    abort the request (fail-closed). They must never swallow exceptions.

    on_startup / on_shutdown are called once at server init/teardown.
    The remaining hooks are called per-request in this order:
        on_session_start → on_request → [tool executes] → on_response → on_session_end
    """

    async def on_startup(self) -> None:
        """Called once when the server starts. Raises on misconfiguration (T8, T11)."""
        ...

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        """Called when a new MCP session opens (after initialize/initialized)."""
        ...

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        """Called before the tool handler executes. May mutate ctx; must not mutate req."""
        ...

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        """Called after the tool handler returns, before sending to the client."""
        ...

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        """Called when the MCP session closes. Used for audit finalisation."""
        ...

    async def on_shutdown(self) -> None:
        """Called once when the server shuts down cleanly."""
        ...
