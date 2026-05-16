"""Stateless HMAC-signed session tokens (T7).

Replaces the in-memory session store. A session_id is a signed token:

    <nonce_b64>.<sig_b64>

where sig = HMAC-SHA256(secret, nonce_b64 + "|" + transport). Verification
recomputes the MAC and constant-time compares — no server-side state, so
sessions survive horizontal scaling, instance recycling, and cold starts.
The previous in-memory store did not: it was a per-process dict, so a token
minted on one instance was unknown to every other instance (and to the same
instance after a restart) — the T7-001 "unknown session" rejection.

Security properties preserved from the store model:
  T7-001 fixation        — an attacker cannot forge a valid signature without
                            the secret; unsigned/foreign IDs are rejected.
  T7-003 cross-transport — transport is bound into the MAC, so a token minted
                            for one transport fails verification on another.
  T7-004 context bleed   — there is no per-session server state to bleed.

ACCEPTED RISK — this is a session-CONTINUITY binding, not an auth credential.
A token has no expiry and no principal/tenant claim, so a leaked token is
replayable until the signing secret is rotated. This matches the prior store
model (its session IDs were equally bearer-equivalent) and is acceptable ONLY
because request authentication and per-principal authorization are enforced
elsewhere: mcp-armor's AuthEngine (T1) when enabled, or — as in the VitalSync
sidecar where T1/T2 are disabled — the upstream server's own bearer-token
validation. A deployment that disables T1 here MUST terminate authentication
upstream; the session token alone grants nothing. Rotating ARMOR_SESSION_SECRET
invalidates every outstanding token (global revocation).
"""

from __future__ import annotations

import base64
import hmac
import os
from hashlib import sha256

from ..exceptions import SessionError

# 256-bit minimum — matches the HMAC-SHA256 output width.
_MIN_SECRET_BYTES = 32
# 144-bit nonce — collision-free at any realistic session volume.
_NONCE_BYTES = 18
# A well-formed token is ~70 chars (24-char nonce + '.' + 43-char sig). Reject
# anything wildly larger BEFORE computing the HMAC: the session header is not
# size-capped upstream, so an attacker could otherwise force an unbounded HMAC
# over attacker-sized input on every unauthenticated request.
_MAX_TOKEN_LEN = 256
_ENV_VAR = "ARMOR_SESSION_SECRET"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class SessionSigner:
    """Mints and verifies stateless HMAC session tokens."""

    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        if len(secret) < _MIN_SECRET_BYTES:
            raise ValueError(
                f"session secret too short: need >= {_MIN_SECRET_BYTES} bytes, "
                f"got {len(secret)}"
            )
        self._secret = secret

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> SessionSigner:
        """Build from ARMOR_SESSION_SECRET.

        Fail-closed: raise if the secret is absent or too short. There is
        deliberately no ephemeral fallback — a per-process random key would
        reintroduce the exact multi-instance failure this class exists to fix
        (a token minted by one instance rejected by every other instance).
        """
        src = os.environ if env is None else env
        raw = src.get(_ENV_VAR, "")
        if not raw:
            raise RuntimeError(
                f"{_ENV_VAR} is not set — refusing to start with an unstable "
                f"session secret. Set it (>= {_MIN_SECRET_BYTES} bytes, from a "
                f"secret manager) so sessions verify across instances."
            )
        return cls(raw.encode())

    def _sig(self, nonce_b64: str, transport: str) -> str:
        msg = f"{nonce_b64}|{transport}".encode()
        return _b64(hmac.new(self._secret, msg, sha256).digest())

    def mint(self, transport: str) -> str:
        """Return a fresh signed session token bound to `transport`."""
        nonce_b64 = _b64(os.urandom(_NONCE_BYTES))
        return f"{nonce_b64}.{self._sig(nonce_b64, transport)}"

    def verify(self, token: str, transport: str) -> None:
        """Raise SessionError unless `token` is a valid signature for `transport`."""
        if not token or len(token) > _MAX_TOKEN_LEN or token.count(".") != 1:
            raise SessionError(
                "Malformed session token — not server-issued "
                "(possible session fixation, T7-001)"
            )
        nonce_b64, sig = token.split(".")
        if not nonce_b64 or not sig:
            raise SessionError(
                "Malformed session token — not server-issued "
                "(possible session fixation, T7-001)"
            )
        expected = self._sig(nonce_b64, transport)
        if not hmac.compare_digest(sig, expected):
            # Either a forged/foreign token (T7-001) or a token minted for a
            # different transport replayed here (T7-003). Opaque on purpose —
            # the caller maps this to JSON-RPC -32006 with a generic message.
            raise SessionError(
                "Session token signature mismatch — possible session fixation "
                "or cross-transport replay (T7-001/T7-003)"
            )
