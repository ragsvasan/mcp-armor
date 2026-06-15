"""T12 — Insufficient Logging: hash-chained append-only audit log."""

from __future__ import annotations

import asyncio
import hashlib
import hmac as _hmac
import json
import logging
import os
import threading
import time
import uuid
from pathlib import Path

from ..context import CoSAIContext
from ..exceptions import AuditChainError
from ..types import MCPRequest, MCPResponse

log = logging.getLogger("mcp_armor.audit")

# Fields included in the chain hash — every auditable field except chain_hash itself.
# F6 fix: `seq` (monotonic 0-based sequence number) is part of the hashed body so
# the position of every record is cryptographically bound — a truncated prefix no
# longer matches the recorded high-water mark.
_CHAIN_FIELDS = (
    "ts",
    "seq",
    "entry_id",
    "parent_id",
    "session_id",
    "user_id",
    "tenant_id",
    "event",
    "method",
    "params_digest",
    "prev_hash",
)


def _canonical(record: dict) -> bytes:
    """Stable serialization of auditable fields for hash-chain input."""
    body = {k: record[k] for k in _CHAIN_FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def _get_hmac_key() -> bytes | None:
    """Read ARMOR_AUDIT_HMAC_KEY from env (hex-encoded).  Returns None if unset."""
    raw = os.environ.get("ARMOR_AUDIT_HMAC_KEY", "").strip()
    if not raw:
        return None
    return bytes.fromhex(raw)


def _compute_chain_hmac(key: bytes, canonical_bytes: bytes) -> str:
    return _hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Sync I/O helpers — called via asyncio.to_thread to avoid blocking the loop
# ---------------------------------------------------------------------------


def _sync_write_hwm(hwm_path: Path, count: int, head: str) -> None:
    # Use a per-call unique tmp file name to prevent concurrent writers from
    # clobbering each other's tmp file before the atomic replace.
    import uuid as _uuid_mod

    tmp = Path(str(hwm_path) + f".{_uuid_mod.uuid4().hex}.tmp")
    tmp.write_text(json.dumps({"count": count, "head": head}))
    tmp.replace(hwm_path)  # atomic on POSIX


def _sync_append_record(log_path: Path, record: dict) -> None:
    with open(log_path, "a") as f:
        f.write(json.dumps(record) + "\n")


def _sync_seed_state(log_path: Path) -> tuple[int, str]:
    """Read existing log and return (count, prev_hash) without full verification."""
    count = 0
    prev = "0" * 64
    if log_path.exists() and log_path.is_file():
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                prev = entry["chain_hash"]
                count += 1
    return count, prev


def _sync_verify_chain(
    log_path: Path,
    hwm_path: Path,
    hmac_key: bytes | None = None,
    hmac_key_prev: bytes | None = None,
) -> tuple[int, str]:
    """
    Verify the hash chain.  Returns (count, last_hash).
    Raises AuditChainError on any violation.
    This is the synchronous implementation; call via asyncio.to_thread.

    Fix 7 (key rotation): if current-key HMAC fails but prev-key matches,
    accept the record with a warning so key rotation doesn't crash startup.
    Fix 11 (HMAC sticky marker): if the .hmac_enabled sidecar exists but
    hmac_key is None, raise AuditChainError to prevent silent downgrade.
    """
    import logging as _logging

    _log = _logging.getLogger("mcp_armor.audit")

    # Fix 11: enforce sticky HMAC — if marker exists without key, reject startup.
    marker = Path(str(log_path) + ".hmac_enabled")
    if marker.exists() and hmac_key is None:
        raise AuditChainError(
            "HMAC was previously enabled for this log — set ARMOR_AUDIT_HMAC_KEY "
            f"or remove {marker} to acknowledge the downgrade (security risk)"
        )

    prev = "0" * 64
    count = 0
    with open(log_path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditChainError(f"Audit log malformed at line {lineno}") from exc
            if entry.get("seq") != count:
                raise AuditChainError(
                    f"Audit chain sequence gap at line {lineno} — expected "
                    f"seq={count}, got {entry.get('seq')!r} (records deleted?)"
                )
            if entry.get("prev_hash") != prev:
                raise AuditChainError(f"Audit chain prev_hash mismatch at line {lineno} — tampered")
            canonical = _canonical(entry)
            expected = hashlib.sha256(canonical).hexdigest()
            if entry.get("chain_hash") != expected:
                raise AuditChainError(
                    f"Audit chain broken at line {lineno} — log may have been tampered"
                )
            # HMAC verification when key is present
            if hmac_key is not None:
                stored_hmac = entry.get("chain_hmac")
                if stored_hmac is None:
                    raise AuditChainError(
                        f"Audit chain HMAC missing at line {lineno} — "
                        "ARMOR_AUDIT_HMAC_KEY is set but record lacks chain_hmac "
                        "(possible tampering or record predates HMAC enforcement)"
                    )
                expected_hmac = _compute_chain_hmac(hmac_key, canonical)
                if not _hmac.compare_digest(stored_hmac, expected_hmac):
                    # Fix 7: try previous key before failing (key rotation support).
                    if hmac_key_prev is not None:
                        prev_expected = _compute_chain_hmac(hmac_key_prev, canonical)
                        if _hmac.compare_digest(stored_hmac, prev_expected):
                            _log.warning(
                                "Audit record %d verified with previous HMAC key "
                                "— rotation pending",
                                lineno,
                            )
                        else:
                            raise AuditChainError(
                                f"Audit chain HMAC mismatch at line {lineno} — "
                                "log was rewritten or HMAC key changed"
                            )
                    else:
                        raise AuditChainError(
                            f"Audit chain HMAC mismatch at line {lineno} — "
                            "log was rewritten or HMAC key changed"
                        )
            prev = entry["chain_hash"]
            count += 1

    # High-water-mark enforcement (same logic as before)
    hwm = _sync_read_hwm(hwm_path)
    if hwm is None:
        if count > 0:
            raise AuditChainError(
                "Audit high-water-mark sidecar is absent for a non-empty "
                "log — cannot prove the log has not been rolled back "
                "(trailing records may have been deleted with the sidecar)"
            )
    else:
        hwm_count, hwm_head = hwm
        if count < hwm_count:
            raise AuditChainError(
                f"Audit log truncated — sidecar records {hwm_count} entries, "
                f"file has {count} (trailing records deleted / rolled back)"
            )
        if count == hwm_count and prev != hwm_head:
            raise AuditChainError(
                "Audit log head hash does not match the recorded high-water "
                "mark — log was rewritten"
            )
    return count, prev


def _sync_read_hwm(hwm_path: Path) -> tuple[int, str] | None:
    """Return (count, head_chain_hash) from the sidecar, or None if absent."""
    if not hwm_path.exists():
        return None
    try:
        data = json.loads(hwm_path.read_text())
        return int(data["count"]), str(data["head"])
    except (json.JSONDecodeError, KeyError, ValueError, OSError) as exc:
        raise AuditChainError(
            "Audit high-water-mark sidecar is unreadable or malformed — "
            "cannot prove the log has not been rolled back"
        ) from exc


class AuditEngine:
    """
    Immutable hash-chained append-only audit log.

    chain_hash = sha256(canonical JSON of all auditable fields)
    This ensures that tampering ANY field — user_id, method, event, ts, etc. —
    breaks the chain and is detected by _verify_chain on next startup.

    Optional HMAC signing (Fix 4): set ARMOR_AUDIT_HMAC_KEY (hex bytes) in the
    environment to add an unforgeable ``chain_hmac`` field to every record.
    Without the key, the chain can be truncated-and-recalculated by anyone
    with write access to the log file; with the key, doing so requires the key.

    Covers:
    - T12-001: No execution trace (cannot reconstruct agent decision chain)
    - T12-002: Log tampering (chain broken = tamper detected on startup)
    - T12-003: PII in logs (params stored as SHA-256 digest only)
    - T12-004: Missing parent_id (cannot build DAG for concurrent calls)

    Format: JSON Lines. Each entry:
      {"ts", "entry_id", "parent_id", "session_id", "user_id", "tenant_id",
       "event", "method", "params_digest", "prev_hash", "chain_hash"[, "chain_hmac"]}

    All file I/O is dispatched via asyncio.to_thread — the event loop is never
    blocked by disk operations (Fix 1).
    """

    def __init__(
        self,
        path: str | Path = "/var/log/mcp-armor/audit.jsonl",
        verify_on_startup: bool = True,
        require_hmac: bool = False,
    ) -> None:
        self._path = Path(path)
        self._verify_on_startup = verify_on_startup
        # A6: when True, on_startup refuses to start without ARMOR_AUDIT_HMAC_KEY
        # (unless ARMOR_AUDIT_ALLOW_UNSIGNED=1). Defaults False so direct/test
        # construction is unaffected; the production from_config path passes True.
        self._require_hmac = require_hmac
        self._lock = threading.Lock()
        # Fix 1 (concurrent writes): async callers must hold this lock across
        # _write() + asyncio.to_thread(I/O) so seq assignment and disk write
        # are atomic from the event loop's perspective.
        self._async_lock: asyncio.Lock | None = None
        self._prev_hash = "0" * 64  # genesis
        self._seq = 0  # F6: next sequence number (0-based, monotonic)
        # F6: tamper-evident high-water mark sidecar.
        self._hwm_path = Path(str(self._path) + ".hwm")
        # Fix 6: read and validate HMAC key once at init; fail fast on bad hex.
        self._hmac_key: bytes | None = self._load_hmac_key("ARMOR_AUDIT_HMAC_KEY")
        # Fix 7: previous HMAC key for rotation grace-period verification.
        self._hmac_key_prev: bytes | None = self._load_hmac_key("ARMOR_AUDIT_HMAC_KEY_PREV")

    @staticmethod
    def _load_hmac_key(env_var: str) -> bytes | None:
        """Read and validate a hex-encoded HMAC key from the environment.

        Returns None if the env var is unset or empty.
        Raises ConfigError at startup if the value is not valid hex.
        """
        from ..config import ConfigError

        raw = os.environ.get(env_var, "").strip()
        if not raw:
            return None
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise ConfigError(
                f"{env_var} is not valid hex-encoded bytes — "
                "set it to a hex string (e.g. openssl rand -hex 32)"
            ) from exc
        # 256-bit floor — matches the HMAC-SHA256 output width and the session
        # signer's _MIN_SECRET_BYTES. A short key (e.g. ARMOR_AUDIT_HMAC_KEY=00)
        # would pass the A6 not-None gate while providing trivial key strength.
        if len(key) < 32:
            raise ConfigError(
                f"{env_var} is too short ({len(key)} bytes) — minimum 32 bytes "
                "(256 bits) for HMAC-SHA256 (e.g. openssl rand -hex 32)"
            )
        return key

    async def on_startup(self) -> None:
        # A6: require an HMAC signing key unless explicitly opted out. Without it
        # the chain is forgeable by anyone with write access to the log. This
        # fail-fast check runs BEFORE _async_lock is created so a refused startup
        # leaves the engine fully uninitialised (no half-started state that a
        # caller could write genesis records into after catching the error).
        if (
            self._require_hmac
            and self._hmac_key is None
            and os.environ.get("ARMOR_AUDIT_ALLOW_UNSIGNED") != "1"
        ):
            raise AuditChainError(
                "T12 audit is enabled but ARMOR_AUDIT_HMAC_KEY is not set — the "
                "hash chain would be tamper-evident but forgeable (truncate-and-"
                "recompute). Set ARMOR_AUDIT_HMAC_KEY (e.g. `openssl rand -hex 32`), "
                "or set ARMOR_AUDIT_ALLOW_UNSIGNED=1 / T12.require_hmac_key=false "
                "to accept an unsigned chain in a dev profile."
            )
        await asyncio.to_thread(self._path.parent.mkdir, parents=True, exist_ok=True)
        marker = Path(str(self._path) + ".hmac_enabled")
        # A4: rollback-to-empty detection. The chain verification (which holds
        # the HWM-absent guard) only runs when the log file exists, so an
        # attacker who deletes the log makes path.exists() False and startup
        # would otherwise seed from empty with NO verification. The HWM sidecar
        # and the .hmac_enabled marker persist independently of the log, so if
        # either survives while the log is gone the full history was erased —
        # refuse to start instead of silently re-seeding an empty chain.
        if self._verify_on_startup and not self._path.exists():
            if self._hwm_path.exists() or marker.exists():
                raise AuditChainError(
                    "Audit log is absent but its high-water-mark sidecar / HMAC "
                    "marker still exists — the log was deleted or rolled back to "
                    "empty (T12-002). Restore the log, or remove "
                    f"{self._hwm_path} and {marker} to acknowledge the loss."
                )
        # A6 (honesty): the silent-failure combination — no key, chain verify
        # disabled, but a .hmac_enabled marker present — means a truncate-and-
        # recompute attack is undetectable on this boot. Surface it loudly.
        if self._hmac_key is None and marker.exists() and not self._verify_on_startup:
            log.error(
                "SECURITY: HMAC key absent, chain_verify_on_startup disabled, and a "
                ".hmac_enabled marker is present — truncate-and-recompute tampering is "
                "undetectable on this startup. Restore ARMOR_AUDIT_HMAC_KEY or re-enable "
                "chain_verify_on_startup."
            )
        # Fix 11: create HMAC-enabled marker file on first startup with key set.
        if self._hmac_key is not None and not marker.exists():
            marker.touch()
        # Create the async lock only after all fail-fast checks pass, so a refused
        # startup never leaves a partially-initialised engine.
        self._async_lock = asyncio.Lock()
        if self._verify_on_startup and self._path.exists():
            # The log existed at the check above; guard the TOCTOU window where a
            # concurrent deleter removes it before verification opens it — surface
            # as a tamper alarm, not a bare FileNotFoundError.
            try:
                await self._verify_chain_async()
            except FileNotFoundError as exc:
                raise AuditChainError(
                    "Audit log vanished between the existence check and verification "
                    "— possible concurrent deletion (T12-002)"
                ) from exc
        else:
            await self._seed_state()

    async def _seed_state(self) -> None:
        """Initialise seq/prev_hash from an existing log without full verify."""
        count, prev = await asyncio.to_thread(_sync_seed_state, self._path)
        with self._lock:
            self._seq = count
            self._prev_hash = prev

    def _verify_chain(self) -> None:
        """
        Synchronous chain verification — for tests and startup code that runs
        outside an event loop.  Production code should call _verify_chain_async()
        to avoid blocking the event loop.
        """
        count, prev = _sync_verify_chain(
            self._path, self._hwm_path, self._hmac_key, self._hmac_key_prev
        )
        with self._lock:
            self._seq = count
            self._prev_hash = prev
        if count:
            _sync_write_hwm(self._hwm_path, count, prev)

    async def _verify_chain_async(self) -> None:
        """Async entry point for chain verification — runs sync logic off-thread."""
        count, prev = await asyncio.to_thread(
            _sync_verify_chain,
            self._path,
            self._hwm_path,
            self._hmac_key,
            self._hmac_key_prev,
        )
        with self._lock:
            self._seq = count
            self._prev_hash = prev
        # Re-anchor the sidecar to the now-verified tail.
        if count:
            await asyncio.to_thread(_sync_write_hwm, self._hwm_path, count, prev)

    def _write_sync(self, event: str, ctx: CoSAIContext, method: str, params_digest: str) -> str:
        """
        Synchronous write for testing and legacy callers.
        Performs file I/O directly on the calling thread, holding the lock
        for the duration so that file-order matches chain-link order.
        DO NOT call from async code — use _append() instead.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        hmac_key = self._hmac_key  # Fix 6: use pre-validated key from __init__
        entry_id = str(uuid.uuid4())
        with self._lock:
            prev_hash = self._prev_hash
            seq = self._seq
            record: dict = {
                "ts": time.time(),
                "seq": seq,
                "entry_id": entry_id,
                "parent_id": ctx.audit_parent_id,
                "session_id": ctx.session_id,
                "user_id": ctx.user_id,
                "tenant_id": ctx.tenant_id,
                "event": event,
                "method": method,
                "params_digest": params_digest,
                "prev_hash": prev_hash,
            }
            canonical = _canonical(record)
            chain_hash = hashlib.sha256(canonical).hexdigest()
            record["chain_hash"] = chain_hash
            if hmac_key is not None:
                record["chain_hmac"] = _compute_chain_hmac(hmac_key, canonical)
            # Append to file INSIDE the lock so file-order == chain-link order
            _sync_append_record(self._path, record)
            self._prev_hash = chain_hash
            self._seq = seq + 1
            new_seq = self._seq
        # HWM write is outside the lock (contention-sensitive, non-blocking)
        _sync_write_hwm(self._hwm_path, new_seq, chain_hash)
        return entry_id

    def _write(
        self,
        event: str,
        ctx: CoSAIContext,
        method: str,
        params_digest: str,
        extra: dict | None = None,
    ) -> tuple[str, dict]:
        """
        Build and return (entry_id, record) under the lock.
        Does NOT perform I/O — the caller dispatches I/O via asyncio.to_thread.
        """
        entry_id = str(uuid.uuid4())
        hmac_key = self._hmac_key  # Fix 6: use pre-validated key from __init__
        with self._lock:
            prev_hash = self._prev_hash
            seq = self._seq
            record: dict = {
                "ts": time.time(),
                "seq": seq,
                "entry_id": entry_id,
                "parent_id": ctx.audit_parent_id,
                "session_id": ctx.session_id,
                "user_id": ctx.user_id,
                "tenant_id": ctx.tenant_id,
                "event": event,
                "method": method,
                "params_digest": params_digest,
                "prev_hash": prev_hash,
            }
            if extra:
                record.update(extra)
            canonical = _canonical(record)
            chain_hash = hashlib.sha256(canonical).hexdigest()
            record["chain_hash"] = chain_hash
            if hmac_key is not None:
                record["chain_hmac"] = _compute_chain_hmac(hmac_key, canonical)
            self._prev_hash = chain_hash
            self._seq = seq + 1
            new_seq = self._seq
        return entry_id, record, new_seq, chain_hash

    async def _append(
        self,
        event: str,
        ctx: CoSAIContext,
        method: str,
        params_digest: str,
        extra: dict | None = None,
    ) -> str:
        """Build the record and persist it atomically under the async lock.

        Fix 1 (concurrent writes): the async lock ensures that seq assignment
        (_write) and the corresponding disk write (asyncio.to_thread) are one
        atomic unit for all async callers — no two coroutines can interleave
        their in-memory state with another's I/O dispatch.
        """
        # If the async lock has not been initialised yet (e.g. called before
        # on_startup in tests), fall back to an unguarded write so tests that
        # don't call on_startup still work.
        lock = self._async_lock
        if lock is None:
            lock = asyncio.Lock()
        async with lock:
            entry_id, record, new_seq, chain_hash = self._write(
                event, ctx, method, params_digest, extra
            )
            await asyncio.to_thread(_sync_append_record, self._path, record)
            # Advance HWM off-thread; don't block the loop
            await asyncio.to_thread(_sync_write_hwm, self._hwm_path, new_seq, chain_hash)
        return entry_id

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        await self._append("session_start", ctx, method="", params_digest="")
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        digest = hashlib.sha256(str(req.params).encode()).hexdigest()
        entry_id = await self._append("request", ctx, req.method, digest)
        return ctx.with_audit_parent(entry_id)

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        digest = hashlib.sha256((resp.raw_body or "").encode()).hexdigest()
        await self._append("response", ctx, method="", params_digest=digest)
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        await self._append("session_end", ctx, method="", params_digest="")

    async def on_shutdown(self) -> None:
        pass
