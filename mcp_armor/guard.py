"""CoSAIGuard — the main composition class. Assembles the engine chain and drives hooks."""

from __future__ import annotations

import functools
import logging
from pathlib import Path
from typing import Any, Callable

from .config import ArmorConfig, load_config
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
from .exceptions import CoSAIException, to_jsonrpc_error
from .types import MCPRequest, MCPResponse

log = logging.getLogger(__name__)


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
    # Factory — typed config
    # -------------------------------------------------------------------------

    @classmethod
    def from_config(cls, path: str | Path = "cosai.yaml") -> "CoSAIGuard":
        """Build a fully configured guard from a cosai.yaml file."""
        cfg: ArmorConfig = load_config(path)
        return cls._from_armor_config(cfg)

    @classmethod
    def _from_armor_config(cls, cfg: ArmorConfig) -> "CoSAIGuard":
        """Build from a typed ArmorConfig (also callable directly from tests)."""
        engines: list[ProtectionEngine] = []

        # T12 wraps everything — must be first in request chain, last in response chain
        if cfg.t12 is not None:
            engines.append(AuditEngine(
                path=cfg.t12.path,
                verify_on_startup=cfg.t12.chain_verify_on_startup,
            ))

        if cfg.t1 is not None:
            engines.append(AuthEngine(
                require_dpop=cfg.t1.require_dpop,
                jti_cache_size=cfg.t1.jti_cache_size,
                token_expiry_max_secs=cfg.t1.token_expiry_max_secs,
                jwks=cfg.t1.jwks,
                issuer=cfg.t1.issuer,
                audience=cfg.t1.audience,
                endpoint_uri=cfg.t1.endpoint_uri,
                dpop_max_age_secs=cfg.t1.dpop_max_age_secs,
                dpop_future_skew_secs=cfg.t1.dpop_future_skew_secs,
            ))

        if cfg.t7 is not None:
            engines.append(SessionEngine(bind_to_dpop=cfg.t7.bind_to_dpop))

        if cfg.t8 is not None:
            engines.append(NetworkEngine(
                allow_public_bind=cfg.t8.allow_public_bind,
                block_rfc1918_ssrf=cfg.t8.block_rfc1918_ssrf,
            ))

        if cfg.t11 is not None:
            engines.append(SupplyChainEngine(
                tool_allowlist=list(cfg.t11.tool_allowlist) if cfg.t11.tool_allowlist else None,
                require_registry_signature=cfg.t11.require_registry_signature,
                levenshtein_threshold=cfg.t11.levenshtein_threshold,
                registry_public_key=cfg.t11.registry_public_key,
            ))

        if cfg.t2 is not None:
            engines.append(AuthzEngine(
                tool_policies=cfg.t2.tool_policies,
                default_deny=cfg.t2.default_deny,
                destructive_token_ttl_seconds=cfg.t2.destructive_token_ttl_seconds,
            ))

        if cfg.t3 is not None:
            engines.append(ValidationEngine(
                max_payload_bytes=cfg.t3.max_payload_bytes,
                strict_schema=cfg.t3.strict_schema,
            ))

        if cfg.t4 is not None:
            engines.append(BoundaryEngine(
                scan_call_args=cfg.t4.scan_call_args,
            ))

        if cfg.t10 is not None:
            engines.append(ResourceEngine(
                max_calls_per_session=cfg.t10.max_calls_per_session,
                max_wall_clock_secs=cfg.t10.max_wall_clock_secs,
                loop_depth_limit=cfg.t10.loop_depth_limit,
                heartbeat_interval_secs=cfg.t10.heartbeat_interval_secs,
            ))

        if cfg.t6 is not None:
            engines.append(IntegrityEngine(
                fail_on_drift=cfg.t6.fail_on_drift,
                tool_allowlist=list(cfg.t6.tool_allowlist) if cfg.t6.tool_allowlist else None,
                typosquat_distance=cfg.t6.typosquat_distance,
            ))

        if cfg.t5 is not None:
            engines.append(PIIEngine(profile=cfg.t5.profile))

        if cfg.t9 is not None:
            engines.append(TrustEngine(
                max_output_length=cfg.t9.max_output_length,
                strip_injection_patterns=cfg.t9.strip_injection_patterns,
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
            set_context(ctx)
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
            set_context(ctx)
        return ctx

    async def _run_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        for engine in reversed(self._engines):
            ctx = await engine.on_response(ctx, resp)
            set_context(ctx)
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
                return await fn(*args, **kwargs)
            return wrapper
        return decorator
