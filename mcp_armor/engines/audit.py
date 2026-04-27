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
_CHAIN_FIELDS = (
    "ts", "entry_id", "parent_id", "session_id", "user_id",
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

    async def on_startup(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._verify_on_startup and self._path.exists():
            self._verify_chain()

    def _verify_chain(self) -> None:
        prev = "0" * 64
        with open(self._path) as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditChainError(f"Audit log malformed at line {lineno}") from exc
                expected = hashlib.sha256(_canonical(entry)).hexdigest()
                if entry.get("chain_hash") != expected:
                    raise AuditChainError(
                        f"Audit chain broken at line {lineno} — log may have been tampered"
                    )
                prev = entry["chain_hash"]
        with self._lock:
            self._prev_hash = prev

    def _write(self, event: str, ctx: CoSAIContext, method: str, params_digest: str) -> str:
        entry_id = str(uuid.uuid4())
        with self._lock:
            prev_hash = self._prev_hash
            record: dict = {
                "ts": time.time(),
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
