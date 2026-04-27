"""CoSAIGuard — the main composition class. Assembles the engine chain and drives hooks."""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any, Callable

import yaml

from .context import CoSAIContext, set_context
from .engines.audit import AuditEngine
from .engines.auth import AuthEngine
from .engines.authz import AuthzEngine
from .engines.base import ProtectionEngine
from .engines.boundary import BoundaryEngine
from .engines.integrity import IntegrityEngine
from .engines.network import NetworkEngine
from .engines.protection import ProtectionEngine as PIIEngine
from .engines.resources import ResourceEngine
from .engines.session import SessionEngine
from .engines.supply_chain import SupplyChainEngine
from .engines.trust import TrustEngine
from .engines.validation import ValidationEngine
from .types import MCPRequest, MCPResponse


class CoSAIGuard:
    """
    Assembles the 12-engine protection chain.

    The chain runs in this fixed order — engines may not be reordered:

    REQUEST:   audit → auth → session → authz → validation → boundary → resources → integrity
    RESPONSE:  boundary → protection → trust → resources → audit

    Engines are driven by CoSAIGuard; they must not call each other directly.
    """

    def __init__(self, engines: list[ProtectionEngine]) -> None:
        self._engines = engines

    # -------------------------------------------------------------------------
    # Factory
    # -------------------------------------------------------------------------

    @classmethod
    def from_config(cls, path: str | Path = "cosai.yaml") -> "CoSAIGuard":
        """Build a fully configured guard from a cosai.yaml file."""
        with open(path) as f:
            cfg = yaml.safe_load(f)

        t = cfg.get("threats", {})

        def enabled(key: str) -> bool:
            return t.get(key, {}).get("enabled", True)

        engines: list[ProtectionEngine] = []

        # T12 wraps everything — must be first in request chain, last in response chain
        if enabled("T12"):
            audit_cfg = t.get("T12", {})
            engines.append(AuditEngine(
                path=audit_cfg.get("path", "/var/log/mcp-armor/audit.jsonl"),
                verify_on_startup=audit_cfg.get("chain_verify_on_startup", True),
            ))

        if enabled("T1"):
            t1 = t.get("T1", {})
            engines.append(AuthEngine(
                require_dpop=t1.get("require_dpop", True),
                jti_cache_size=t1.get("jti_cache_size", 10_000),
                token_expiry_max_secs=t1.get("token_expiry_max_secs", 3600),
            ))

        if enabled("T7"):
            t7 = t.get("T7", {})
            engines.append(SessionEngine(bind_to_dpop=t7.get("bind_session_to_dpop", True)))

        if enabled("T8"):
            t8 = t.get("T8", {})
            engines.append(NetworkEngine(
                allow_public_bind=t8.get("allow_public_bind", False),
                block_rfc1918_ssrf=t8.get("block_rfc1918", True),
            ))

        if enabled("T11"):
            t11 = t.get("T11", {})
            engines.append(SupplyChainEngine(
                tool_allowlist=t11.get("tool_allowlist") or None,
                require_registry_signature=t11.get("require_registry_signature", False),
            ))

        if enabled("T2"):
            t2 = t.get("T2", {})
            engines.append(AuthzEngine(
                tool_policies=t2.get("tool_policies"),
                default_deny=t2.get("default_policy", "deny") == "deny",
            ))

        if enabled("T3"):
            t3 = t.get("T3", {})
            engines.append(ValidationEngine(
                max_payload_bytes=t3.get("max_payload_bytes", 65_536),
                strict_schema=t3.get("strict_schema", True),
            ))

        if enabled("T4"):
            engines.append(BoundaryEngine())

        if enabled("T10"):
            t10 = t.get("T10", {})
            engines.append(ResourceEngine(
                max_calls_per_session=t10.get("max_calls_per_session", 100),
                max_wall_clock_secs=t10.get("max_wall_clock_secs", 300),
                loop_depth_limit=t10.get("loop_depth_limit", 10),
                heartbeat_interval_secs=t10.get("heartbeat_interval_secs", 30),
            ))

        if enabled("T6"):
            t6 = t.get("T6", {})
            engines.append(IntegrityEngine(
                fail_on_drift=t6.get("fail_on_drift", True),
                tool_allowlist=t6.get("tool_allowlist"),
            ))

        if enabled("T5"):
            t5 = t.get("T5", {})
            engines.append(PIIEngine(profile=t5.get("profile", "pci")))

        if enabled("T9"):
            t9 = t.get("T9", {})
            engines.append(TrustEngine(
                max_output_length=t9.get("max_output_length", 32_768),
                strip_injection_patterns=t9.get("strip_injection_patterns", True),
            ))

        return cls(engines)

    @classmethod
    def default(cls) -> "CoSAIGuard":
        """Build with sensible defaults — no config file required."""
        return cls([
            AuditEngine(),
            AuthEngine(),
            SessionEngine(),
            NetworkEngine(),
            AuthzEngine(),
            ValidationEngine(),
            BoundaryEngine(),
            ResourceEngine(),
            IntegrityEngine(),
            PIIEngine(),
            TrustEngine(),
        ])

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def register_tool_schemas(self, tools: list[dict]) -> None:
        """Forward tools/list result to ValidationEngine for T3 schema validation."""
        for engine in self._engines:
            if isinstance(engine, ValidationEngine):
                engine.register_tools(tools)

    async def startup(self) -> None:
        for engine in self._engines:
            await engine.on_startup()

    async def shutdown(self) -> None:
        for engine in self._engines:
            await engine.on_shutdown()

    async def open_session(self, ctx: CoSAIContext) -> CoSAIContext:
        for engine in self._engines:
            ctx = await engine.on_session_start(ctx)
        return ctx

    async def close_session(self, ctx: CoSAIContext) -> None:
        for engine in self._engines:
            await engine.on_session_end(ctx)

    # -------------------------------------------------------------------------
    # Per-request hooks (called by adapters)
    # -------------------------------------------------------------------------

    async def _run_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        for engine in self._engines:
            ctx = await engine.on_request(ctx, req)
        return ctx

    async def _run_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        for engine in reversed(self._engines):  # response chain runs in reverse
            ctx = await engine.on_response(ctx, resp)
        return ctx

    # -------------------------------------------------------------------------
    # Framework integration
    # -------------------------------------------------------------------------

    def wrap(self, app: Any) -> Any:
        """Auto-detect framework type and wrap the app."""
        try:
            import fastmcp  # noqa: F401
            if isinstance(app, fastmcp.FastMCP):
                from .adapters.fastmcp import wrap_fastmcp
                return wrap_fastmcp(app, self)
        except ImportError:
            pass

        # Fall back to ASGI
        from .adapters.fastapi import ArmorMiddleware
        return ArmorMiddleware(app, self)

    def asgi(self, app: Any) -> Any:
        """Wrap as ASGI middleware (FastAPI, Starlette, raw ASGI)."""
        from .adapters.fastapi import ArmorMiddleware
        return ArmorMiddleware(app, self)

    def wrap_dispatcher(self, dispatcher: Any) -> Any:
        """Wrap a raw async JSON-RPC dispatcher callable."""
        from .adapters.dispatcher import wrap_dispatcher
        return wrap_dispatcher(dispatcher, self)

    def protect(
        self,
        threats: list[str] | None = None,
        **policy_overrides: Any,
    ) -> Callable:
        """
        Per-tool decorator for fine-grained policy.

        Usage:
            @app.tool()
            @guard.protect(threats=["T3", "T5"], pii_profile="strict")
            async def my_tool(query: str) -> str: ...
        """
        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                # TODO: apply per-tool engine subset and policy overrides
                # For now, full guard applies — per-tool overrides are future work
                return await fn(*args, **kwargs)
            return wrapper
        return decorator
