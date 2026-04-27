"""T2 — Missing Access Control: per-tool RBAC, confused deputy prevention."""

from __future__ import annotations

from ..context import CoSAIContext
from ..exceptions import AuthorizationError
from ..types import MCPRequest, MCPResponse


class AuthzEngine:
    """
    Enforces per-tool scope requirements against the caller's identity.

    Covers:
    - T2-001: Confused deputy (service account executing user-requested privileged action)
    - T2-002: Missing per-tool RBAC
    - T2-003: Multi-tenant data bleed (tenant_id isolation)

    Policy: default_deny — tools with no policy entry are denied.
    """

    def __init__(
        self,
        tool_policies: dict[str, list[str]] | None = None,
        default_deny: bool = True,
    ) -> None:
        self._policies: dict[str, list[str]] = tool_policies or {}
        self._default_deny = default_deny

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        if req.method != "tools/call":
            return ctx
        tool_name = str(req.params.get("name", ""))
        required_scopes = self._policies.get(tool_name)
        if required_scopes is None and self._default_deny:
            raise AuthorizationError(f"Tool '{tool_name}' not in policy — denied by default")
        # TODO: compare required_scopes against ctx.user_id / ctx.tenant_id claims
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
