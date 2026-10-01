"""T7/T2 — MCP 2026-07-28 request envelope + ``_meta`` trust (CoSAI v2.0 TN-04, SD-02).

Opt-in (``T7.enforce_request_envelope``), ported from cosai-mcp P2
(Mnemo dec_4a33244bff, dec_cf145130e8). Runs after T1 AuthEngine and T7
SessionEngine so the authenticated identity is already on the context.

On every request:

1. ``_meta`` reconciliation (SD-02) — identity / tenant / role claims in
   ``params._meta`` must restate the authenticated principal
   (``ctx.user_id`` / ``ctx.tenant_id`` / ``ctx.scopes``) and can never expand
   it. A conflicting or unreconcilable claim raises ``MetaTrustError`` (T2).
   Name matching is a safety net: application code must take identity only
   from the authenticated context, never from ``_meta``.
2. Header/body consistency (TN-04) — a request carrying MCP 2026-07-28
   signals (a ``_meta`` protocol version, or ``MCP-Protocol-Version`` /
   ``Mcp-Method`` / ``Mcp-Name`` / ``Mcp-Param-*`` routing headers) must have
   headers that agree exactly with the body (-32020) and a supported version
   (-32022). Pre-2026 session requests without those signals pass unchanged.

Scope: effective on ArmorMiddleware (and the sidecar, which runs it) and on
``wrap_dispatcher`` (``_meta`` reconciliation only — header checks are
HTTP-only). The FastMCP per-tool hook and ``@guard.protect`` synthesize the
request without the client's ``_meta`` or headers, so the engine is inert
there; run ArmorMiddleware in front of those servers.

Adapters should populate ``MCPRequest.raw_header_pairs`` with the raw ASGI
header list so duplicated routing headers are detected; otherwise the
de-duplicated ``raw_headers`` mapping is used.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import Any

from ..context import CoSAIContext
from ..request_envelope import (
    AuthenticatedPrincipal,
    MetaTrustError,
    RequestMetadataError,
    reconcile_meta,
    validate_request_metadata,
)
from ..types import MCPRequest, MCPResponse

_MAX_REGISTERED_TOOLS = 4096

log = logging.getLogger(__name__)


class EnvelopeEngine:
    """Reconcile ``_meta`` claims and enforce the 2026-07-28 request envelope."""

    def __init__(self, *, allowed_meta_keys: Iterable[str] | None = None) -> None:
        self._allowed_meta_keys = (
            frozenset(allowed_meta_keys) if allowed_meta_keys is not None else None
        )
        self._tool_schemas: dict[str, Any] = {}
        self._cap_warned = False

    def register_tools(self, tools: list[dict[str, Any]]) -> None:
        """Record tool inputSchemas so ``Mcp-Param-*`` headers can be checked.

        First write wins (as in ValidationEngine): a later or attacker-
        influenced manifest cannot remap an annotation already registered —
        an operator pin at startup or the first observed tools/list. Bounded.
        """
        dropped = 0
        for tool in tools:
            name = tool.get("name") if isinstance(tool, dict) else None
            if not isinstance(name, str) or name in self._tool_schemas:
                continue
            if len(self._tool_schemas) >= _MAX_REGISTERED_TOOLS:
                dropped += 1
                continue
            self._tool_schemas[name] = tool.get("inputSchema")
        if dropped and not self._cap_warned:
            self._cap_warned = True
            # Count only — tool names are upstream-controlled strings.
            log.warning(
                "EnvelopeEngine: tool schema registry is full (%d); %d tool(s) not "
                "registered — modern tools/call to them will be rejected as unknown.",
                _MAX_REGISTERED_TOOLS, dropped,
            )

    async def on_startup(self) -> None:
        return None

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        principal = AuthenticatedPrincipal(
            subject=ctx.user_id or "",
            tenant=ctx.tenant_id,
            scopes=frozenset(ctx.scopes),
        )
        meta = req.params.get("_meta")
        if meta is not None and not isinstance(meta, Mapping):
            raise MetaTrustError(["_meta"])
        reconcile_meta(meta, principal, allowed_keys=self._allowed_meta_keys)

        if req.transport != "http":
            # Header/body consistency is a Streamable-HTTP property: rpc/stdio
            # transports carry no routing headers to compare.
            return ctx
        headers: Any = req.raw_header_pairs if req.raw_header_pairs else req.raw_headers
        body = {"jsonrpc": "2.0", "method": req.method, "params": dict(req.params)}
        try:
            validate_request_metadata(
                headers,
                body,
                # Always the registry, even empty: a modern tools/call before
                # this worker observed tools/list is rejected (unknown tool)
                # rather than letting a missing Mcp-Param-* header through.
                tool_schemas=self._tool_schemas,
            )
        except RequestMetadataError as exc:
            # A request with no 2026-07-28 signals at all is a legacy session
            # request: the only outcome that is not a violation.
            if exc.reason != "missing_meta":
                raise
        except TypeError as exc:
            raise RequestMetadataError(-32600, "Invalid Request",
                                       reason="invalid_headers") from exc
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        # Schemas are NOT learned here: CoSAIGuard._run_response commits a
        # tools/list manifest to register_tools() only after the WHOLE response
        # chain (incl. T11 allowlist/signature, T6) accepted it.
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        return None

    async def on_shutdown(self) -> None:
        return None
