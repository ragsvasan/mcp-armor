"""T10 — Resource Management: budget enforcement, loop detection, heartbeat."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from ..context import CoSAIContext
from ..exceptions import ResourceExceededError
from ..types import CONTENT_BEARING_METHODS, MCPRequest, MCPResponse

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
        self._sessions_lock = threading.Lock()
        self._reaper_task: asyncio.Task | None = None

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
                    f"Tool argument nesting depth {depth} exceeds limit {self._max_arg_depth} (T10-003)"
                )

        return ctx.with_budget(budget.increment())

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        with self._sessions_lock:
            self._session_last_seen.pop(ctx.session_id, None)

    async def on_shutdown(self) -> None:
        await self.close()
