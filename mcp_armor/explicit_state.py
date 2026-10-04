"""T7 explicit-state integrity for MCP 2026-07-28 — CoSAI v2.0 SD-01 / SD-03.

The 2026-07-28 release removes protocol sessions; cross-call state moves into
references the client carries. v2.0 §3.2.12 distinguishes two kinds, each with
its own control (Mnemo dec_4a33244bff):

* **Client-held sealed state** — e.g. the ``requestState`` of an
  ``InputRequiredResult`` (MRTR). The server keeps no copy, so the value must be
  opaque to the client, integrity-protected, and rejected on any verification
  failure. :class:`RequestStateSealer` seals it with AES-256-GCM, binding the
  authenticated principal, the originating request, and an expiry inside the
  seal (L3), with key rotation and an optional single-use replay cache.

* **Server-held references** — task IDs and continuation handles. The server
  retains the state, so the reference must be unguessable, carry no meaning to
  the client, be scoped to principal and tenant, expire, be revocable, and be
  enumerable per principal for incident response. :class:`HandleRegistry`.

Every verification failure raises one generic error type with one message —
never an oracle telling an attacker *which* check failed.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import heapq
import json
import logging
import os
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import AuthorizationError, SessionError

_FORMAT = "v1"
_NONCE_BYTES = 12
_KEY_BYTES = 32
_KID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_MAX_STATE_CHARS = 64 * 1024
_MAX_TTL_SECONDS = 3600
# NIST SP 800-38D §8.3: random 96-bit nonces are safe to 2^32 invocations per
# key; stop well short and force rotation.
_MAX_SEALS_PER_KEY = 2**31
_MAX_SPENT_ENTRIES = 1_000_000
_MAX_SPENT_PER_OWNER = 10_000
# Per-tenant partition: one tenant's principals (however many) cannot consume
# more than this share of the global cache.
_MAX_SPENT_PER_TENANT = _MAX_SPENT_ENTRIES // 4
# Guaranteed floor: an owner below this many entries is admitted even when the
# global cap is reached (up to a 2x hard ceiling), so many colluding
# principals cannot lock every other user out.
_OWNER_FLOOR = 8

logger = logging.getLogger(__name__)


def _decrement(counts: dict[Any, int], key: Any) -> None:
    left = counts.get(key, 1) - 1
    if left > 0:
        counts[key] = left
    else:
        counts.pop(key, None)


class StateVerificationError(SessionError):
    """T7: requestState failed verification. Deliberately uninformative."""

    def __init__(self) -> None:
        super().__init__("invalid or expired requestState")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _eq(a: Any, b: str) -> bool:
    """Constant-time string equality that accepts any Unicode (compare_digest
    raises TypeError on non-ASCII str)."""
    if not isinstance(a, str):
        return False
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def request_fingerprint(method: str, params: Mapping[str, Any]) -> str:
    """Identifier for the originating request: method + SHA-256 of the canonical
    salient params (``requestState``, ``inputResponses`` and ``_meta`` excluded —
    they legitimately differ between the original request and its retry)."""
    salient = {k: v for k, v in params.items()
               if k not in ("requestState", "inputResponses", "_meta")}
    # No default=str: distinct non-JSON values must not collide with strings.
    # Raises TypeError/ValueError for non-JSON-native params or NaN.
    digest = hashlib.sha256(
        json.dumps(salient, sort_keys=True, separators=(",", ":"),
                   allow_nan=False).encode()
    ).hexdigest()
    return f"{method}:{digest}"


class SpentStore(Protocol):
    """Shared replay cache for single-use requestState across instances."""

    def add_if_absent(self, jti: str, expires_at: float) -> bool:
        """Atomically record *jti* until *expires_at*; False if already present."""
        ...


def _is_weak_key(key: bytes) -> bool:
    """Heuristic guard against non-random sealing keys. 32 uniformly random
    bytes have ~30 distinct values and are essentially never all printable
    ASCII, so either condition means a constant, pattern or passphrase key
    (a passphrase is not a key — derive one with HKDF/scrypt instead)."""
    return len(set(key)) < 16 or all(0x20 <= b <= 0x7E for b in key)


class RequestStateSealer:
    """Seal / open MRTR ``requestState`` with AES-256-GCM.

    Token: ``v1.<kid>.<base64url(nonce || ciphertext||tag)>``. The AAD binds the
    format and key id, so a token cannot be replayed under another key or
    format. The sealed plaintext carries the principal, request fingerprint,
    expiry, a unique id, and the server payload. Each key seals at most
    2^31 tokens per process (random-nonce GCM bound); rotate before that.

    ``audience`` (this server / resource identifier) is bound into the AAD so a
    fleet sharing keys cannot redeem one server's state at another; ``tenant``
    is bound per token.

    ``single_use`` (default on) replay protection is process-local: across
    replicas or a restart a token remains replayable until it expires. Pass a
    shared ``spent_store`` (atomic add-if-absent, e.g. Redis ``SET NX EX``) for
    multi-instance deployments.

    Usage::

        sealer = RequestStateSealer({"k1": key_bytes}, active_kid="k1",
                                    audience="https://mcp.example.com/mcp")
        state = sealer.seal({"step": 2}, principal=sub, tenant=tenant,
                            request_id=request_fingerprint("tools/call", params))
        ...
        payload = sealer.open(returned_state, principal=sub, tenant=tenant,
                              request_id=request_fingerprint("tools/call", params))
    """

    def __init__(
        self,
        keys: Mapping[str, bytes],
        *,
        active_kid: str,
        audience: str,
        default_ttl_seconds: int = 300,
        single_use: bool = True,
        spent_store: SpentStore | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not keys:
            raise ValueError("at least one sealing key is required")
        for kid, key in keys.items():
            if not _KID_RE.match(kid):
                raise ValueError(f"invalid key id {kid!r}")
            if len(key) != _KEY_BYTES:
                raise ValueError("sealing keys must be exactly 32 bytes (AES-256)")
            if _is_weak_key(key):
                raise ValueError(
                    f"sealing key {kid!r} looks non-random (repeated bytes or a "
                    "printable passphrase) — generate it with os.urandom(32) / "
                    "secrets.token_bytes(32) or a KMS")
        if not isinstance(audience, str) or not audience:
            raise ValueError("audience (this server's resource identifier) is required")
        if active_kid not in keys:
            raise ValueError("active_kid must be one of the configured keys")
        if not 0 < default_ttl_seconds <= _MAX_TTL_SECONDS:
            raise ValueError(f"default_ttl_seconds must be 1..{_MAX_TTL_SECONDS}")
        self._aead = {kid: AESGCM(key) for kid, key in keys.items()}
        self._active = active_kid
        self._ttl = default_ttl_seconds
        self._single_use = single_use
        self._audience = audience
        self._store = spent_store
        self._clock = clock
        # jti -> (principal, tenant); expiry heap for O(log n) incremental purge;
        # per-owner counts so one principal cannot fill the cache for others.
        self._spent: dict[str, tuple[str, str]] = {}
        self._spent_heap: list[tuple[float, str]] = []
        self._spent_per_owner: dict[tuple[str, str], int] = {}
        self._spent_per_tenant: dict[str, int] = {}
        self._seals: dict[str, int] = dict.fromkeys(keys, 0)
        self._lock = threading.Lock()

    @staticmethod
    def generate_key() -> bytes:
        """A fresh 256-bit sealing key (CSPRNG)."""
        return os.urandom(_KEY_BYTES)

    def _aad(self, kid: str) -> bytes:
        return b"|".join((b"cosai-requestState", _FORMAT.encode(), kid.encode(),
                          hashlib.sha256(self._audience.encode("utf-8")).digest()))

    def seal(
        self,
        payload: Mapping[str, Any],
        *,
        principal: str,
        request_id: str,
        tenant: str,
        ttl_seconds: int | None = None,
    ) -> str:
        """Return an opaque sealed ``requestState`` string."""
        if not isinstance(principal, str) or not isinstance(request_id, str) \
                or not principal or not request_id:
            raise ValueError("principal and request_id are required")
        if not isinstance(tenant, str) or not tenant:
            raise ValueError("tenant is required (single-tenant servers pass a fixed "
                             "sentinel such as 'default')")
        ttl = self._ttl if ttl_seconds is None else ttl_seconds
        if not 0 < ttl <= _MAX_TTL_SECONDS:
            raise ValueError(f"ttl_seconds must be 1..{_MAX_TTL_SECONDS}")
        body = json.dumps({
            "p": principal,
            "t": tenant,
            "r": request_id,
            "exp": self._clock() + ttl,
            "jti": secrets.token_hex(16),
            "d": dict(payload),
        }, separators=(",", ":")).encode()
        with self._lock:
            if self._seals[self._active] >= _MAX_SEALS_PER_KEY:
                raise RuntimeError("sealing key usage limit reached; rotate active_kid")
            self._seals[self._active] += 1
        nonce = os.urandom(_NONCE_BYTES)
        ct = self._aead[self._active].encrypt(nonce, body, self._aad(self._active))
        token = f"{_FORMAT}.{self._active}.{_b64(nonce + ct)}"
        if len(token) > _MAX_STATE_CHARS:
            raise ValueError("sealed requestState exceeds the maximum size")
        return token

    def open(self, token: Any, *, principal: str, request_id: str,
             tenant: str) -> dict[str, Any]:
        """Verify and return the sealed payload, or raise :class:`StateVerificationError`.

        Rejects: wrong format/type/size, unknown key id, tampering (GCM tag),
        expiry, a different principal / tenant / audience, a different
        originating request, and —
        with ``single_use`` — any second presentation.
        """
        try:
            if not isinstance(token, str) or len(token) > _MAX_STATE_CHARS:
                raise StateVerificationError
            fmt, kid, blob = token.split(".", 2)
            if fmt != _FORMAT or kid not in self._aead:
                raise StateVerificationError
            raw = _unb64(blob)
            if len(raw) <= _NONCE_BYTES:
                raise StateVerificationError
            body = self._aead[kid].decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:],
                                           self._aad(kid))
            claims = json.loads(body)
        except (StateVerificationError, ValueError, binascii.Error, InvalidTag,
                UnicodeDecodeError, RecursionError):
            raise StateVerificationError from None
        now = self._clock()
        if (
            not isinstance(claims, dict)
            or not isinstance(claims.get("exp"), (int, float))
            or claims["exp"] <= now
            or not isinstance(principal, str) or not isinstance(request_id, str)
            or not isinstance(tenant, str)
            or not _eq(claims.get("p"), principal)
            or not _eq(claims.get("t"), tenant)
            or not _eq(claims.get("r"), request_id)
            or not isinstance(claims.get("d"), dict)
        ):
            raise StateVerificationError
        if self._single_use:
            jti = claims.get("jti")
            if not isinstance(jti, str) or not jti:
                raise StateVerificationError
            if self._store is not None:
                try:
                    fresh = self._store.add_if_absent(jti, float(claims["exp"]))
                except Exception:
                    logger.exception("requestState spent_store failed; rejecting")
                    raise StateVerificationError from None
                if not fresh:
                    raise StateVerificationError
                result_d: dict[str, Any] = claims["d"]
                return result_d
            owner = (principal, tenant)
            with self._lock:
                while self._spent_heap and self._spent_heap[0][0] <= now:
                    _, old = heapq.heappop(self._spent_heap)
                    o = self._spent.pop(old, None)
                    if o is not None:
                        _decrement(self._spent_per_owner, o)
                        _decrement(self._spent_per_tenant, o[1])
                if jti in self._spent:
                    raise StateVerificationError
                mine = self._spent_per_owner.get(owner, 0)
                total = len(self._spent)
                in_tenant = self._spent_per_tenant.get(tenant, 0)
                # Each cap (tenant, global) admits owners below the floor up
                # to a 2x hard ceiling, so Sybils inside one tenant (e.g. the
                # single-tenant 'default' sentinel) cannot lock out its peers.
                if (mine >= _MAX_SPENT_PER_OWNER
                        or (in_tenant >= _MAX_SPENT_PER_TENANT
                            and (mine >= _OWNER_FLOOR
                                 or in_tenant >= 2 * _MAX_SPENT_PER_TENANT))
                        or (total >= _MAX_SPENT_ENTRIES
                            and (mine >= _OWNER_FLOOR or total >= 2 * _MAX_SPENT_ENTRIES))):
                    logger.warning("requestState replay cache full (owner, tenant or global)")
                    raise StateVerificationError
                self._spent[jti] = owner
                self._spent_per_owner[owner] = self._spent_per_owner.get(owner, 0) + 1
                self._spent_per_tenant[tenant] = self._spent_per_tenant.get(tenant, 0) + 1
                heapq.heappush(self._spent_heap, (float(claims["exp"]), jti))
        result: dict[str, Any] = claims["d"]
        return result


# ---------------------------------------------------------------------------
# Server-held references
# ---------------------------------------------------------------------------

class HandleError(AuthorizationError):
    """T2: handle is unknown, expired, revoked, or not the caller's. Uninformative."""

    def __init__(self) -> None:
        super().__init__("unknown or unauthorized handle")


@dataclass(frozen=True)
class HandleRecord:
    handle: str
    principal: str
    tenant: str
    kind: str
    created_at: float
    expires_at: float


class HandleRegistry:
    """Mint and authorize opaque server-held references (task IDs, cursors).

    Handles are 256-bit CSPRNG tokens with no embedded identifiers. Possession
    is NOT authority: :meth:`resolve` re-checks the authenticated principal and
    tenant on every use (v2.0 takes the stricter position than the Tasks
    extension's bearer semantics). Revoking a principal's grant revokes all of
    its handles and invokes ``on_revoke`` for each (e.g. cancel the in-flight
    task, and never release its result).
    """

    def __init__(
        self,
        *,
        max_handles: int = 100_000,
        max_handles_per_principal: int = 1_000,
        max_handles_per_tenant: int | None = None,
        max_ttl_seconds: int = 24 * 3600,
        on_revoke: Callable[[HandleRecord], None] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._records: dict[str, HandleRecord] = {}
        self._max = max_handles
        self._max_per_principal = max_handles_per_principal
        self._counts: dict[tuple[str, str], int] = {}
        # Tenant partition (default: a quarter of the registry) so one tenant's
        # principals cannot exhaust capacity for other tenants.
        self._max_per_tenant = (max_handles_per_tenant if max_handles_per_tenant is not None
                                else max(1, max_handles // 4))
        self._tenant_counts: dict[str, int] = {}
        self._next_purge = 0.0
        self._max_ttl = max_ttl_seconds
        self._on_revoke = on_revoke
        self._clock = clock
        self._lock = threading.Lock()

    def _drop(self, handle: str) -> HandleRecord | None:
        record = self._records.pop(handle, None)
        if record is not None:
            _decrement(self._counts, (record.principal, record.tenant))
            _decrement(self._tenant_counts, record.tenant)
        return record

    def _purge(self, now: float, *, force: bool = False) -> None:
        # Amortised: a full sweep at most once a second unless forced.
        if not force and now < self._next_purge:
            return
        self._next_purge = now + 1.0
        for h in [h for h, r in self._records.items() if r.expires_at <= now]:
            self._drop(h)

    def _notify(self, records: list[HandleRecord]) -> None:
        """Run on_revoke for every record even if some callbacks fail."""
        if self._on_revoke is None:
            return
        failures = 0
        for r in records:
            try:
                self._on_revoke(r)
            except Exception:
                failures += 1
                logger.exception("on_revoke callback failed for a %s handle", r.kind)
        if failures:
            raise RuntimeError(f"on_revoke failed for {failures} of {len(records)} handles")

    def mint(self, *, principal: str, tenant: str, kind: str, ttl_seconds: int) -> str:
        if not principal or not tenant:
            raise ValueError("principal and tenant are required")
        if not 0 < ttl_seconds <= self._max_ttl:
            raise ValueError(f"ttl_seconds must be 1..{self._max_ttl}")
        now = self._clock()
        with self._lock:
            self._purge(now)
            if len(self._records) >= self._max:
                self._purge(now, force=True)
            owner = (principal, tenant)
            mine = self._counts.get(owner, 0)
            if len(self._records) >= self._max and (
                    mine >= _OWNER_FLOOR or len(self._records) >= 2 * self._max):
                # Owners below the floor are still admitted (Sybil resistance).
                raise RuntimeError("handle registry is full")
            if self._counts.get(owner, 0) >= self._max_per_principal:
                self._purge(now, force=True)
                if self._counts.get(owner, 0) >= self._max_per_principal:
                    raise RuntimeError("handle limit reached for this principal")
            if self._tenant_counts.get(tenant, 0) >= self._max_per_tenant:
                self._purge(now, force=True)
                in_tenant = self._tenant_counts.get(tenant, 0)
                if in_tenant >= self._max_per_tenant and (
                        self._counts.get(owner, 0) >= _OWNER_FLOOR
                        or in_tenant >= 2 * self._max_per_tenant):
                    raise RuntimeError("handle limit reached for this tenant")
            handle = secrets.token_urlsafe(32)
            self._counts[owner] = self._counts.get(owner, 0) + 1
            self._tenant_counts[tenant] = self._tenant_counts.get(tenant, 0) + 1
            self._records[handle] = HandleRecord(
                handle=handle, principal=principal, tenant=tenant, kind=kind,
                created_at=now, expires_at=now + ttl_seconds,
            )
        return handle

    def resolve(self, handle: Any, *, principal: str, tenant: str,
                kind: str | None = None) -> HandleRecord:
        """Authorize *handle* for this caller or raise :class:`HandleError`."""
        if not isinstance(handle, str) or len(handle) > 256:
            raise HandleError
        now = self._clock()
        with self._lock:
            record = self._records.get(handle)
            if record is not None and record.expires_at <= now:
                self._drop(handle)
                record = None
        if (
            record is None
            or not _eq(principal, record.principal)
            or not _eq(tenant, record.tenant)
            or (kind is not None and record.kind != kind)
        ):
            raise HandleError
        return record

    def revoke(self, handle: Any, *, principal: str, tenant: str) -> bool:
        """Caller-initiated revoke (e.g. ``tasks/cancel``): same principal and
        tenant checks as :meth:`resolve` — possession is not authority.
        Raises :class:`HandleError` if the caller does not own *handle*."""
        record = self.resolve(handle, principal=principal, tenant=tenant)
        return self.admin_revoke(record.handle)

    def admin_revoke(self, handle: str) -> bool:
        """Operator / incident-response revoke with NO ownership check. Never
        wire this to a client-reachable method."""
        with self._lock:
            record = self._drop(handle) if isinstance(handle, str) else None
        if record is not None:
            self._notify([record])
        return record is not None

    def revoke_principal(self, principal: str, tenant: str | None = None) -> list[HandleRecord]:
        """Revoke every handle of *principal* (optionally within *tenant*)."""
        with self._lock:
            doomed = [r for r in self._records.values()
                      if r.principal == principal and (tenant is None or r.tenant == tenant)]
            for r in doomed:
                self._drop(r.handle)
        self._notify(doomed)
        return doomed

    def list_for_principal(self, principal: str,
                           tenant: str | None = None) -> list[HandleRecord]:
        """Live handles for incident response (v2.0 SD-01 L3)."""
        now = self._clock()
        with self._lock:
            self._purge(now, force=True)
            return [r for r in self._records.values()
                    if r.principal == principal and (tenant is None or r.tenant == tenant)]
