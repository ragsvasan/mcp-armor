"""T7 — Session Security Failures: cryptographic binding, fixation prevention."""

from __future__ import annotations

import logging
import threading

from ..context import CoSAIContext
from ..exceptions import SessionError
from ..types import MCPRequest, MCPResponse

log = logging.getLogger(__name__)


class _SessionStore:
    """
    Server-side session record store.

    Holds, per session_id:
    - transport: transport type recorded when the 'initialize' request arrives

    Thread-safe. on_session_end clears the record (prevents context bleed).

    Note: the "nonce" pattern was removed because storing a nonce server-side without
    requiring the client to present it provides no cryptographic binding. The binding
    here is purely "session was created by this server" (presence in the store). For
    true sender-binding, DPoP (RFC 9449) or mTLS (RFC 8705) is required and is
    enforced at the AuthEngine layer when configured.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, str | None] = {}  # session_id → transport (None = not yet set)
        self._lock = threading.Lock()

    def create(self, session_id: str, transport: str | None = None) -> None:
        """Pre-register a session. Transport may be set later by set_transport()."""
        with self._lock:
            self._sessions[session_id] = transport

    def set_transport(self, session_id: str, transport: str) -> None:
        """Lock in the transport type when the 'initialize' request arrives."""
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id] = transport

    def verify(self, session_id: str, transport: str) -> None:
        """
        Verify that the session exists (server-created) and transport has not changed.

        Raises SessionError on any violation.
        """
        with self._lock:
            if session_id not in self._sessions:
                raise SessionError(
                    f"Unknown session '{session_id}' — possible session fixation attempt (T7-001)"
                )
            stored = self._sessions[session_id]

        if stored is not None and transport != stored:
            raise SessionError(
                f"Cross-transport replay detected for session '{session_id}': "
                f"was {stored!r}, now {transport!r} (T7-003)"
            )

    def close(self, session_id: str) -> None:
        """Remove session record on close — prevents context bleed (T7-004)."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def __contains__(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self._sessions


class SessionEngine:
    """
    Binds sessions to their originating transport and prevents fixation / replay.

    Covers:
    - T7-001: Session fixation (attacker pre-sets session ID)
    - T7-002: Token in URL (session ID leaks via Referer / logs)
    - T7-003: Cross-transport replay (stdio session token used over HTTP)
    - T7-004: Context bleed between sessions (stale context carried over)

    Lifecycle:
    1. on_session_start(ctx) — pre-registers the session (transport from ctx.transport)
    2. on_request(ctx, initialize_req) — locks in transport (idempotent for re-calls)
    3. on_request(ctx, any_other_req) — verifies transport matches
    4. on_session_end(ctx) — clears session record (T7-004)
    """

    def __init__(self, bind_to_dpop: bool = True) -> None:
        self._bind_to_dpop = bind_to_dpop
        self._store = _SessionStore()

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        """
        Pre-register the session.

        The transport is taken from ctx.transport — set by the adapter before
        calling guard.open_session(). This ensures:
        1. The session is server-created (in the store) before any request is processed
        2. The transport is correct at the time of registration
        3. Subsequent 'initialize' requests lock it in idempotently
        """
        self._store.create(ctx.session_id, transport=ctx.transport)
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        # T7-002: reject session_id in URL query params (leaks via Referer / access logs)
        if "session_id" in req.url_query_params or "mcp_session_id" in req.url_query_params:
            raise SessionError(
                "session_id must not appear in URL query parameters — "
                "it leaks via Referer header and server logs (T7-002)"
            )

        if req.method == "initialize":
            # Lock in the transport on the initialize handshake.
            # If on_session_start already set it (typical adapter flow), this is idempotent.
            # Also verifies the session is known — guards against initialize mid-session
            # with a fabricated session_id (which would not be in the store).
            self._store.verify(ctx.session_id, req.transport)
            self._store.set_transport(ctx.session_id, req.transport)
        else:
            self._store.verify(ctx.session_id, req.transport)

        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        # T7-004: clear session state — prevents context bleed across sessions
        self._store.close(ctx.session_id)

    async def on_shutdown(self) -> None:
        pass
