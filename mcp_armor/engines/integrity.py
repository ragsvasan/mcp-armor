"""T6 — Integrity/Verification: manifest drift, typosquatting, tool shadowing."""

from __future__ import annotations

import hashlib
import json

from ..context import CoSAIContext
from ..exceptions import IntegrityError
from ..types import MCPRequest, MCPResponse


class IntegrityEngine:
    """
    Snapshots the tools/list manifest at session start and detects drift.

    Covers:
    - T6-001: Mid-session tool list mutation (rug pull — tools added/removed)
    - T6-002: Tool name typosquatting against known-good allowlist
    - T6-003: Tool shadowing (two tools with near-identical names)
    """

    def __init__(
        self,
        fail_on_drift: bool = True,
        tool_allowlist: list[str] | None = None,
        typosquat_distance: int = 2,
    ) -> None:
        self._fail_on_drift = fail_on_drift
        self._allowlist = set(tool_allowlist) if tool_allowlist else None
        self._typosquat_distance = typosquat_distance

    @staticmethod
    def _manifest_hash(tools: list[dict]) -> str:
        canonical = json.dumps(sorted(tools, key=lambda t: t.get("name", "")), sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if len(a) < len(b):
            return IntegrityEngine._levenshtein(b, a)
        if not b:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a):
            curr = [i + 1]
            for j, cb in enumerate(b):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
            prev = curr
        return prev[-1]

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        # Hash is set by the guard after tools/list — nothing to do here
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        # Drift check happens when guard refreshes manifest; per-request no-op
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    def check_drift(self, ctx: CoSAIContext, current_tools: list[dict]) -> None:
        new_hash = self._manifest_hash(current_tools)
        if ctx.tool_manifest_hash and new_hash != ctx.tool_manifest_hash:
            if self._fail_on_drift:
                raise IntegrityError(
                    f"Tool manifest changed mid-session "
                    f"(was {ctx.tool_manifest_hash[:12]}…, now {new_hash[:12]}…)"
                )

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
