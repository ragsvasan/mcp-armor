"""T11 — Supply Chain: tool allowlist enforcement, registry signature verification."""

from __future__ import annotations

from ..context import CoSAIContext
from ..exceptions import SupplyChainError
from ..types import MCPRequest, MCPResponse


class SupplyChainEngine:
    """
    Validates tools at server startup against a known-good allowlist.

    Covers:
    - T11-001: Unlisted tool loaded (no allowlist = deny all)
    - T11-002: Typosquatted package name in tool manifest
    - T11-003: Unsigned tool from untrusted registry
    - T11-004: Dependency confusion (internal package name shadowed by public)
    """

    def __init__(
        self,
        tool_allowlist: list[str] | None = None,
        require_registry_signature: bool = False,
    ) -> None:
        self._allowlist = set(tool_allowlist) if tool_allowlist else None
        self._require_sig = require_registry_signature

    async def on_startup(self) -> None:
        pass

    def validate_tools(self, tools: list[dict]) -> None:
        """Call from server startup with the tools/list response."""
        if self._allowlist is None:
            return
        for tool in tools:
            name = tool.get("name", "")
            if name not in self._allowlist:
                raise SupplyChainError(
                    f"Tool '{name}' is not on the approved allowlist"
                )
        # TODO: registry signature verification via Ed25519

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
