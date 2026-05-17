"""T12 — Insufficient Logging: hash-chained append-only audit log."""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from pathlib import Path

from ..context import CoSAIContext
from ..exceptions import AuditChainError
from ..types import MCPRequest, MCPResponse

# Fields included in the chain hash — every auditable field except chain_hash itself.
# F6 fix: `seq` (monotonic 0-based sequence number) is part of the hashed body so
# the position of every record is cryptographically bound — a truncated prefix no
# longer matches the recorded high-water mark.
_CHAIN_FIELDS = (
    "ts", "seq", "entry_id", "parent_id", "session_id", "user_id",
    "tenant_id", "event", "method", "params_digest", "prev_hash",
)


def _canonical(record: dict) -> bytes:
    """Stable serialization of auditable fields for hash-chain input."""
    body = {k: record[k] for k in _CHAIN_FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


class AuditEngine:
    """
    Immutable hash-chained append-only audit log.

    chain_hash = sha256(canonical JSON of all auditable fields)
    This ensures that tampering ANY field — user_id, method, event, ts, etc. —
    breaks the chain and is detected by _verify_chain on next startup.

    Covers:
    - T12-001: No execution trace (cannot reconstruct agent decision chain)
    - T12-002: Log tampering (chain broken = tamper detected on startup)
    - T12-003: PII in logs (params stored as SHA-256 digest only)
    - T12-004: Missing parent_id (cannot build DAG for concurrent calls)

    Format: JSON Lines. Each entry:
      {"ts", "entry_id", "parent_id", "session_id", "user_id", "tenant_id",
       "event", "method", "params_digest", "prev_hash", "chain_hash"}
    """

    def __init__(
        self,
        path: str | Path = "/var/log/mcp-armor/audit.jsonl",
        verify_on_startup: bool = True,
    ) -> None:
        self._path = Path(path)
        self._verify_on_startup = verify_on_startup
        self._lock = threading.Lock()
        self._prev_hash = "0" * 64  # genesis
        self._seq = 0  # F6: next sequence number (0-based, monotonic)
        # F6: tamper-evident high-water mark sidecar. Records the count and the
        # head chain_hash so trailing-record deletion (rollback) is detected,
        # not just in-place mutation.
        self._hwm_path = Path(str(self._path) + ".hwm")

    async def on_startup(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._verify_on_startup and self._path.exists():
            self._verify_chain()
        else:
            # No log yet — seed seq/prev from any existing file without verify
            self._seed_state()

    def _read_hwm(self) -> tuple[int, str] | None:
        """Return (count, head_chain_hash) from the sidecar, or None if absent."""
        if not self._hwm_path.exists():
            return None
        try:
            data = json.loads(self._hwm_path.read_text())
            return int(data["count"]), str(data["head"])
        except (json.JSONDecodeError, KeyError, ValueError, OSError) as exc:
            raise AuditChainError(
                "Audit high-water-mark sidecar is unreadable or malformed — "
                "cannot prove the log has not been rolled back"
            ) from exc

    def _write_hwm(self, count: int, head: str) -> None:
        tmp = Path(str(self._hwm_path) + ".tmp")
        tmp.write_text(json.dumps({"count": count, "head": head}))
        tmp.replace(self._hwm_path)  # atomic

    def _seed_state(self) -> None:
        """Initialise seq/prev_hash from an existing log without full verify."""
        count = 0
        prev = "0" * 64
        if self._path.exists():
            with open(self._path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    prev = entry["chain_hash"]
                    count += 1
        with self._lock:
            self._seq = count
            self._prev_hash = prev

    def _verify_chain(self) -> None:
        prev = "0" * 64
        count = 0
        with open(self._path) as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditChainError(f"Audit log malformed at line {lineno}") from exc
                # F6: sequence numbers must be contiguous and 0-based — a
                # deleted interior record breaks this even if hashes re-chain.
                if entry.get("seq") != count:
                    raise AuditChainError(
                        f"Audit chain sequence gap at line {lineno} — expected "
                        f"seq={count}, got {entry.get('seq')!r} (records deleted?)"
                    )
                if entry.get("prev_hash") != prev:
                    raise AuditChainError(
                        f"Audit chain prev_hash mismatch at line {lineno} — tampered"
                    )
                expected = hashlib.sha256(_canonical(entry)).hexdigest()
                if entry.get("chain_hash") != expected:
                    raise AuditChainError(
                        f"Audit chain broken at line {lineno} — log may have been tampered"
                    )
                prev = entry["chain_hash"]
                count += 1

        # F6: enforce the tamper-evident high-water mark. Truncating trailing
        # records leaves a self-consistent prefix that the per-line hash check
        # alone cannot detect; the recorded count + head hash catches it.
        #
        # BLOCK[3] fix: a MISSING sidecar must FAIL CLOSED when the log is
        # non-empty. Previously an absent sidecar (`_read_hwm() is None`) was
        # silently treated as "nothing to anchor against" and the chain was
        # re-anchored to whatever tail the file currently had — so an attacker
        # who truncated the append-only log and then `rm`'d the one-line
        # sidecar laundered the rollback completely (no AuditChainError, fresh
        # hwm written over the truncated tail). Deleting a sibling file
        # requires no more privilege than truncating the log, so the prior
        # behaviour gave zero residual protection against a rollback. We now
        # treat sidecar absence exactly like a malformed sidecar: a non-empty
        # verified log with no high-water mark cannot be proven un-rolled-back.
        # The genuine first-run case (a brand-new / never-appended log) is the
        # `count == 0` guard below: an empty log has no records to roll back,
        # so an absent sidecar there is not a false positive.
        hwm = self._read_hwm()
        if hwm is None:
            if count > 0:
                raise AuditChainError(
                    "Audit high-water-mark sidecar is absent for a non-empty "
                    "log — cannot prove the log has not been rolled back "
                    "(trailing records may have been deleted with the sidecar)"
                )
            # count == 0: genuine first run / empty log — nothing to anchor,
            # no rollback possible. Fall through and (re)write a fresh hwm.
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
            if count > hwm_count:
                # More records than the sidecar knew about can happen after a
                # crash between log append and sidecar update; only the prefix
                # is anchored. Re-anchor forward (monotonic, never shrink).
                pass
        with self._lock:
            self._seq = count
            self._prev_hash = prev
        # Re-anchor the sidecar to the now-verified tail.
        if count:
            self._write_hwm(count, prev)

    def _write(self, event: str, ctx: CoSAIContext, method: str, params_digest: str) -> str:
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
            chain_hash = hashlib.sha256(_canonical(record)).hexdigest()
            record["chain_hash"] = chain_hash
            with open(self._path, "a") as f:
                f.write(json.dumps(record) + "\n")
            self._prev_hash = chain_hash
            self._seq = seq + 1
            # F6: advance the tamper-evident high-water mark after every
            # append so a later trailing-record deletion is detectable.
            self._write_hwm(self._seq, chain_hash)
        return entry_id

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        self._write("session_start", ctx, method="", params_digest="")
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        digest = hashlib.sha256(str(req.params).encode()).hexdigest()
        entry_id = self._write("request", ctx, req.method, digest)
        return ctx.with_audit_parent(entry_id)

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        digest = hashlib.sha256((resp.raw_body or "").encode()).hexdigest()
        self._write("response", ctx, method="", params_digest=digest)
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        self._write("session_end", ctx, method="", params_digest="")

    async def on_shutdown(self) -> None:
        pass
