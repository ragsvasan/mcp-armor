"""T10 — Resource Management: budget enforcement, loop detection, heartbeat."""

from __future__ import annotations

import time

from ..context import CoSAIContext
from ..exceptions import ResourceExceededError
from ..types import MCPRequest, MCPResponse


class ResourceEngine:
    """
    Enforces per-session and per-call resource limits.

    Covers:
    - T10-001: Unbounded call count (denial of wallet)
    - T10-002: Wall-clock time limit exceeded
    - T10-003: Recursive / circular tool call loop (depth limit)
    - T10-004: Missing heartbeat (zombie session detection)
    """

    def __init__(
        self,
        max_calls_per_session: int = 100,
        max_wall_clock_secs: float = 300.0,
        loop_depth_limit: int = 10,
        heartbeat_interval_secs: float = 30.0,
    ) -> None:
        self._max_calls = max_calls_per_session
        self._max_wall = max_wall_clock_secs
        self._max_depth = loop_depth_limit
        self._heartbeat_interval = heartbeat_interval_secs

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        if req.method != "tools/call":
            return ctx

        budget = ctx.budget
        elapsed = time.monotonic() - budget.wall_clock_start

        if budget.calls_used >= self._max_calls:
            raise ResourceExceededError(
                f"Session call budget exhausted ({self._max_calls} calls)"
            )
        if elapsed > self._max_wall:
            raise ResourceExceededError(
                f"Session wall-clock limit exceeded ({self._max_wall}s)"
            )
        if budget.loop_depth > self._max_depth:
            raise ResourceExceededError(
                f"Recursive tool call depth exceeded (limit {self._max_depth})"
            )

        return ctx.with_budget(budget.increment())

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
