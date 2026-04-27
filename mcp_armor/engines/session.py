"""T7 — Session Security Failures: cryptographic binding, fixation prevention."""

from __future__ import annotations

from ..context import CoSAIContext
from ..exceptions import SessionError
from ..types import MCPRequest, MCPResponse


class SessionEngine:
    """
    Binds sessions cryptographically and prevents fixation / cross-transport replay.

    Covers:
    - T7-001: Session fixation (attacker pre-sets session ID)
    - T7-002: Token in URL (session ID leaks via Referer / logs)
    - T7-003: Cross-transport replay (stdio session token used over HTTP)
    - T7-004: Context bleed between sessions (stale context carried over)
    """

    def __init__(self, bind_to_dpop: bool = True) -> None:
        self._bind_to_dpop = bind_to_dpop

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        # TODO: generate server-side session nonce, bind to transport type
        # TODO: verify session_id was not supplied by client (fixation prevention)
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        # TODO: verify transport has not changed since session_start
        # TODO: reject if session_id appears in URL params
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
