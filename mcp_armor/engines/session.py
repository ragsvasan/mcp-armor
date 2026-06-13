"""T7 — Session Security Failures: stateless HMAC binding, fixation prevention.

Sessions are HMAC-signed tokens (see _session_token.SessionSigner), not entries
in a per-process store. This is the fix for the store's fatal multi-instance
flaw: a token minted on one instance was unknown to every other instance and to
the same instance after a restart, so any horizontally scaled / scale-to-zero
deployment rejected legitimate sessions with a spurious T7-001 "unknown session".
"""

from __future__ import annotations

import logging

from ..context import CoSAIContext
from ..exceptions import SessionError
from ..types import MCPRequest, MCPResponse
from ._session_token import SessionSigner

log = logging.getLogger(__name__)


class SessionEngine:
    """
    Binds sessions to their originating transport and prevents fixation / replay
    — statelessly, via a signed token. No server-side session state exists.

    Scope — transport-bound session CONTINUITY, not a sender-constrained
    credential. The token binds `transport` into its MAC; it intentionally does
    NOT bind a DPoP key thumbprint. DPoP sender-constraint (proof-of-possession,
    rejecting a token presented with the wrong key) is enforced by the T1
    AuthEngine on every request via the access token's `cnf.jkt` claim against
    the presented DPoP proof. A prior `bind_to_dpop` / `bind_session_to_dpop`
    flag here was a no-op label (stored, never read) and has been removed so the
    configuration surface only advertises behaviour the code actually enforces.

    Covers:
    - T7-001: Session fixation (forged / foreign session IDs fail signature check)
    - T7-002: Token in URL (session ID leaks via Referer / logs)
    - T7-003: Cross-transport replay (transport is bound into the signature)
    - T7-004: Context bleed between sessions (no per-session state to bleed)

    Lifecycle:
    1. adapter mints the token via guard.mint_session_id() on 'initialize'
    2. on_request(ctx, req) — verifies the token signature for ctx/req transport
    3. on_session_start / on_session_end — no-ops (stateless by construction)
    """

    def __init__(
        self,
        signer: SessionSigner | None = None,
    ) -> None:
        # Fail-closed: SessionSigner.from_env() raises if ARMOR_SESSION_SECRET
        # is absent — the guard build aborts rather than minting unverifiable
        # tokens. Tests inject an explicit signer.
        self._signer = signer if signer is not None else SessionSigner.from_env()

    @property
    def signer(self) -> SessionSigner:
        """Exposed so the guard can mint a token on a new session."""
        return self._signer

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        # Stateless — nothing to register. The token is minted by the adapter
        # via guard.mint_session_id() and carries its own proof of issuance.
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        # T7-002: reject session_id in URL query params (leaks via Referer / access logs)
        if "session_id" in req.url_query_params or "mcp_session_id" in req.url_query_params:
            raise SessionError(
                "session_id must not appear in URL query parameters — "
                "it leaks via Referer header and server logs (T7-002)"
            )

        # T7-001 / T7-003: the token must carry a valid signature for this
        # transport. A forged ID (fixation) or a token minted for a different
        # transport (cross-transport replay) fails the constant-time compare.
        self._signer.verify(ctx.session_id, req.transport)
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        # T7-004: no per-session state exists — context bleed is structurally
        # impossible, so there is nothing to clear.
        pass

    async def on_shutdown(self) -> None:
        pass
