"""T10 — Resource Management: budget enforcement, loop detection, heartbeat."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from ..context import CoSAIContext
from ..exceptions import ResourceExceededError
from ..types import CONTENT_BEARING_METHODS, BudgetState, MCPRequest, MCPResponse

log = logging.getLogger(__name__)


def _json_depth(obj: Any, current: int = 0) -> int:
    """Return the maximum nesting depth of a JSON-like Python object."""
    if isinstance(obj, dict):
        if not obj:
            return current
        return max(_json_depth(v, current + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return current
        return max(_json_depth(v, current + 1) for v in obj)
    return current


class ResourceEngine:
    """
    Enforces per-session and per-call resource limits.

    Covers:
    - T10-001: Unbounded call count (denial of wallet)
    - T10-002: Wall-clock time limit exceeded
    - T10-003: Recursive / circular tool call loop (depth limit) + JSON argument depth bomb
    - T10-004: Missing heartbeat (zombie session detection)
    """

    def __init__(
        self,
        max_calls_per_session: int = 100,
        max_wall_clock_secs: float = 300.0,
        loop_depth_limit: int = 10,
        heartbeat_interval_secs: float = 30.0,
        max_arg_depth: int = 15,
        eviction_callback: Callable[[str], None] | None = None,
    ) -> None:
        self._max_calls = max_calls_per_session
        self._max_wall = max_wall_clock_secs
        self._max_depth = loop_depth_limit
        self._heartbeat_interval = heartbeat_interval_secs
        self._max_arg_depth = max_arg_depth
        # Fix 9: optional callback called with session_id when a session is evicted.
        # Used by ArmorMiddleware to clean _active_sessions on reaper eviction.
        self._eviction_callback: Callable[[str], None] | None = eviction_callback
        # T10-004: zombie session detection.
        # Maps session_id → last-activity monotonic timestamp.
        self._session_last_seen: dict[str, float] = {}
        # LOW fix (T10-001/002 denial-of-wallet): budget ledger keyed by
        # session_id — which, in SessionSigner-backed deployments, IS the
        # signed HMAC session token (see engines/_session_token.py), so only
        # the holder of a validly-issued token can accumulate/resume budget
        # under a given key. The zombie reaper below only ever removes entries
        # from _session_last_seen (to let the adapter free its per-session
        # context store on idle-eviction); it deliberately never touches this
        # dict. Without this, an adapter that rebuilds a fresh zero-budget
        # CoSAIContext after idle-eviction would let an attacker pacing calls
        # just over heartbeat_interval_secs reset their budget indefinitely.
        # This dict is the source of truth for budget accounting — cleared
        # only on_session_end (explicit close), decoupling the accounting
        # lifetime from the much shorter zombie-reap TTL.
        # Bounded LRU ledger (see _save_budget). Capped so "persist budget across
        # idle-eviction" can't become an unbounded-memory DoS: paths that mint and
        # abandon sessions (HTTP open then zombie-reap, and the per-call
        # wrap_dispatcher) never reach on_session_end, so without a cap this dict
        # would grow one permanent entry per session forever.
        self._session_budgets: OrderedDict[str, BudgetState] = OrderedDict()
        self._max_budget_entries = 50_000
        self._sessions_lock = threading.Lock()
        self._reaper_task: asyncio.Task[None] | None = None

    async def on_startup(self) -> None:
        # Start the background zombie-session reaper.
        # Fix 5: use get_running_loop() — get_event_loop() is deprecated in 3.10+
        self._reaper_task = asyncio.get_running_loop().create_task(
            self._reaper_loop(), name="mcp-armor-resource-reaper"
        )

    async def _reaper_loop(self) -> None:
        """Background task: evict sessions with no activity for heartbeat_interval_secs."""
        while True:
            try:
                await asyncio.sleep(self._heartbeat_interval)
                await self._reap_zombie_sessions()
            except asyncio.CancelledError:
                break
            except Exception as exc:  # pragma: no cover
                log.warning("ResourceEngine reaper error (non-fatal): %s", exc)

    async def _reap_zombie_sessions(self) -> None:
        """Evict sessions that have exceeded the heartbeat interval without activity."""
        now = time.monotonic()
        with self._sessions_lock:
            zombies = [
                sid
                for sid, last in self._session_last_seen.items()
                if now - last > self._heartbeat_interval
            ]
            for sid in zombies:
                del self._session_last_seen[sid]
        for sid in zombies:
            log.warning(
                "ResourceEngine: evicted zombie session %s (no activity for %.1fs, T10-004)",
                sid,
                self._heartbeat_interval,
            )
            # Fix 9: notify adapter so it can clean its own session store.
            if self._eviction_callback is not None:
                try:
                    self._eviction_callback(sid)
                except Exception as exc:  # pragma: no cover
                    log.warning("ResourceEngine eviction_callback error: %s", exc)

    def _restore_budget(self, ctx: CoSAIContext) -> CoSAIContext:
        """
        Return ctx with its budget replaced by the persisted ledger value for
        this session_id, if one exists. Returns ctx unchanged (same object) if
        there is no persisted entry yet, so first-touch behaviour is identical
        to before this fix.
        """
        with self._sessions_lock:
            persisted = self._session_budgets.get(ctx.session_id)
            if persisted is not None:
                self._session_budgets.move_to_end(ctx.session_id)  # mark recently used
        if persisted is not None:
            return ctx.with_budget(persisted)
        return ctx

    def _save_budget(self, session_id: str, budget: BudgetState) -> None:
        with self._sessions_lock:
            self._session_budgets[session_id] = budget
            self._session_budgets.move_to_end(session_id)
            # LRU-evict oldest entries beyond the cap — bounds memory on the
            # mint-and-abandon paths that never reach on_session_end.
            while len(self._session_budgets) > self._max_budget_entries:
                self._session_budgets.popitem(last=False)

    async def close(self) -> None:
        """Cancel the background reaper task. Call from lifespan shutdown."""
        if self._reaper_task is not None and not self._reaper_task.done():
            self._reaper_task.cancel()
            try:
                await self._reaper_task
            except asyncio.CancelledError:
                pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        with self._sessions_lock:
            self._session_last_seen[ctx.session_id] = time.monotonic()
        # Resume the persisted budget (if this session_id/token was seen
        # before and idle-evicted) instead of trusting a freshly-built ctx's
        # zeroed budget. No-op (returns ctx unchanged) on first touch.
        ctx = self._restore_budget(ctx)
        self._save_budget(ctx.session_id, ctx.budget)
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        # T10-004: refresh last-seen on every request to suppress false zombie eviction.
        with self._sessions_lock:
            self._session_last_seen[ctx.session_id] = time.monotonic()

        # F2 fix: count resources/read & prompts/get against the session
        # budget too — otherwise the denial-of-wallet limit only ever sees
        # the single tools/call per request.
        if req.method not in CONTENT_BEARING_METHODS:
            return ctx

        # LOW fix: pull in the persisted ledger before evaluating limits. This
        # is the second (belt-and-suspenders) restore point alongside
        # on_session_start — whichever the adapter actually invokes for a
        # revived session, the persisted budget wins over a rebuilt zero one.
        ctx = self._restore_budget(ctx)
        budget = ctx.budget
        elapsed = time.monotonic() - budget.wall_clock_start

        if budget.calls_used >= self._max_calls:
            raise ResourceExceededError(f"Session call budget exhausted ({self._max_calls} calls)")
        if elapsed > self._max_wall:
            raise ResourceExceededError(f"Session wall-clock limit exceeded ({self._max_wall}s)")
        if budget.loop_depth > self._max_depth:
            raise ResourceExceededError(
                f"Recursive tool call depth exceeded (limit {self._max_depth})"
            )

        # T10-003: reject deeply-nested argument objects (JSON depth bomb).
        args = req.params.get("arguments")
        if args is not None:
            depth = _json_depth(args)
            if depth > self._max_arg_depth:
                raise ResourceExceededError(
                    f"Tool argument nesting depth {depth} exceeds limit "
                    f"{self._max_arg_depth} (T10-003)"
                )

        new_ctx = ctx.with_budget(budget.increment())
        self._save_budget(new_ctx.session_id, new_ctx.budget)
        return new_ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        with self._sessions_lock:
            self._session_last_seen.pop(ctx.session_id, None)
            self._session_budgets.pop(ctx.session_id, None)

    async def on_shutdown(self) -> None:
        await self.close()
