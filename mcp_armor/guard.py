"""CoSAIGuard — the main composition class. Assembles the engine chain and drives hooks."""

from __future__ import annotations

import functools
import logging
import uuid
from collections.abc import Callable
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from .config import ArmorConfig, load_config
from .context import CoSAIContext, set_context

# ContextVar that ASGI/HTTP adapters set per-request so that @guard.protect
# decorators executing inside an active HTTP request see the live CoSAIContext
# (with real JWT scopes, user_id, etc.) rather than a blank stdio context.
# Default is None — indicates no active ASGI request (stdio / test path).
_active_ctx: ContextVar[CoSAIContext | None] = ContextVar("mcp_armor_ctx", default=None)
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
from .exceptions import CoSAIException
from .types import MCPRequest, MCPResponse

log = logging.getLogger(__name__)

_THREAT_ENGINE_TYPES: dict[str, type] = {}  # populated after class definitions below


class CoSAIGuard:
    """
    Assembles the 12-engine protection chain.

    The chain runs in this fixed order — engines may not be reordered:

    REQUEST:   audit → auth → session → authz → validation → boundary → resources → integrity
    RESPONSE:  boundary → protection → trust → resources → audit

    Engines are driven by CoSAIGuard; they must not call each other directly.

    dry_run (NOT FOR PRODUCTION):
    When True, CoSAIException violations are caught, logged at WARNING with full
    detail, and the request proceeds as if no violation occurred.  The audit log
    still records the event tagged with "dry_run": true.  Use ONLY for config
    tuning — dry_run disables all enforcement.
    """

    def __init__(self, engines: list[ProtectionEngine], dry_run: bool = False) -> None:
        self._engines = engines
        if dry_run:
            # B6: hard prod guard. dry_run disables all non-auth enforcement, so
            # shipping it to production silently neuters the middleware. Refuse to
            # construct unless the operator has explicitly acknowledged it via
            # ARMOR_ALLOW_DRY_RUN=1 — a config-file flag alone is too easy to
            # leave on by accident.
            import os

            if os.environ.get("ARMOR_ALLOW_DRY_RUN") != "1":
                raise RuntimeError(
                    "CoSAIGuard: dry_run=True is refused unless ARMOR_ALLOW_DRY_RUN=1 "
                    "is set in the environment. dry_run DISABLES all non-auth "
                    "enforcement and must never reach production. Set the env var "
                    "only on a tuning host to acknowledge this."
                )
            log.error(
                "CoSAIGuard: dry_run=True — ALL non-auth enforcement is DISABLED. "
                "Violations are logged but NOT blocked. NOT FOR PRODUCTION."
            )
        self._dry_run = dry_run

    def mint_session_id(self, transport: str) -> str:
        """Mint the session_id for a brand-new session.

        Delegates to the SessionEngine's stateless HMAC signer when T7 is
        enabled, so the ID is a self-verifying token that survives horizontal
        scaling and instance recycling. Falls back to a CSPRNG UUID only when
        no SessionEngine is configured (T7 disabled) — in that mode there is no
        session verification anyway.
        """
        for engine in self._engines:
            if isinstance(engine, SessionEngine):
                return engine.signer.mint(transport)
        return str(uuid.uuid4())

    # -------------------------------------------------------------------------
    # Factory — typed config
    # -------------------------------------------------------------------------

    @classmethod
    def from_config(cls, path: str | Path = "cosai.yaml") -> CoSAIGuard:
        """Build a fully configured guard from a cosai.yaml file."""
        cfg: ArmorConfig = load_config(path)
        return cls._from_armor_config(cfg)

    @classmethod
    def _from_armor_config(cls, cfg: ArmorConfig) -> CoSAIGuard:
        """Build from a typed ArmorConfig (also callable directly from tests)."""
        engines: list[ProtectionEngine] = []

        # T12 wraps everything — must be first in request chain, last in response chain
        if cfg.t12 is not None:
            engines.append(
                AuditEngine(
                    path=cfg.t12.path,
                    verify_on_startup=cfg.t12.chain_verify_on_startup,
                    require_hmac=cfg.t12.require_hmac_key,
                )
            )

        if cfg.t1 is not None:
            engines.append(
                AuthEngine(
                    require_dpop=cfg.t1.require_dpop,
                    require_jti=cfg.t1.require_jti,
                    jti_cache_size=cfg.t1.jti_cache_size,
                    token_expiry_max_secs=cfg.t1.token_expiry_max_secs,
                    jwks=cfg.t1.jwks,
                    issuer=cfg.t1.issuer,
                    audience=cfg.t1.audience,
                    endpoint_uri=cfg.t1.endpoint_uri,
                    dpop_max_age_secs=cfg.t1.dpop_max_age_secs,
                    dpop_future_skew_secs=cfg.t1.dpop_future_skew_secs,
                    require_cnf_binding=cfg.t1.require_cnf_binding,
                )
            )

        if cfg.t7 is not None:
            engines.append(
                SessionEngine(require_initialized_handshake=cfg.t7.require_initialized_handshake)
            )

        if cfg.t8 is not None:
            engines.append(
                NetworkEngine(
                    allow_public_bind=cfg.t8.allow_public_bind,
                    block_rfc1918_ssrf=cfg.t8.block_rfc1918_ssrf,
                    bind_host=cfg.t8.bind_host,
                    bind_port=cfg.t8.bind_port,
                )
            )

        if cfg.t11 is not None:
            engines.append(
                SupplyChainEngine(
                    # Preserve explicit empty list — None means no allowlist (allow all),
                    # [] means deny all. Using `if cfg.t11.tool_allowlist` would collapse
                    # both to None and silently make empty allowlist into allow-all.
                    tool_allowlist=list(cfg.t11.tool_allowlist)
                    if cfg.t11.tool_allowlist is not None
                    else None,
                    require_registry_signature=cfg.t11.require_registry_signature,
                    levenshtein_threshold=cfg.t11.levenshtein_threshold,
                    registry_public_key=cfg.t11.registry_public_key,
                )
            )

        if cfg.t2 is not None:
            engines.append(
                AuthzEngine(
                    tool_policies=cfg.t2.tool_policies,
                    default_deny=cfg.t2.default_deny,
                    destructive_token_ttl_seconds=cfg.t2.destructive_token_ttl_seconds,
                    echo_confirm_token=cfg.t2.echo_confirm_token,
                )
            )

        if cfg.t3 is not None:
            engines.append(
                ValidationEngine(
                    max_payload_bytes=cfg.t3.max_payload_bytes,
                    strict_schema=cfg.t3.strict_schema,
                    prose_field_names=(
                        frozenset(cfg.t3.prose_field_names)
                        if cfg.t3.prose_field_names is not None
                        else None
                    ),
                )
            )

        if cfg.t4 is not None:
            engines.append(
                BoundaryEngine(
                    scan_call_args=cfg.t4.scan_call_args,
                    scan_responses=cfg.t4.scan_responses,
                )
            )

        if cfg.t10 is not None:
            engines.append(
                ResourceEngine(
                    max_calls_per_session=cfg.t10.max_calls_per_session,
                    max_wall_clock_secs=cfg.t10.max_wall_clock_secs,
                    loop_depth_limit=cfg.t10.loop_depth_limit,
                    heartbeat_interval_secs=cfg.t10.heartbeat_interval_secs,
                )
            )

        if cfg.t6 is not None:
            engines.append(
                IntegrityEngine(
                    fail_on_drift=cfg.t6.fail_on_drift,
                    tool_allowlist=list(cfg.t6.tool_allowlist)
                    if cfg.t6.tool_allowlist is not None
                    else None,
                    typosquat_distance=cfg.t6.typosquat_distance,
                )
            )

        if cfg.t5 is not None:
            engines.append(PIIEngine(profile=cfg.t5.profile))

        if cfg.t9 is not None:
            engines.append(
                TrustEngine(
                    max_output_length=cfg.t9.max_output_length,
                    strip_injection_patterns=cfg.t9.strip_injection_patterns,
                )
            )

        return cls(engines, dry_run=cfg.dry_run)

    @classmethod
    def default(cls) -> CoSAIGuard:
        """Build with sensible defaults — no config file required."""
        return cls(
            [
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
            ]
        )

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def register_tool_schemas(self, tools: list[dict[str, Any]]) -> None:
        """
        Register a tools/list result with all engines that need it at setup time.

        Calls:
        - ValidationEngine.register_tools()  — T3 schema enforcement
        - SupplyChainEngine.validate_tools()  — T11 allowlist + signature check
        - IntegrityEngine.scan_tool_manifest() — T6 typosquat + homoglyph scan
        """
        for engine in self._engines:
            if isinstance(engine, ValidationEngine):
                engine.register_tools(tools)
            elif isinstance(engine, SupplyChainEngine):
                engine.validate_tools(tools)
            elif isinstance(engine, IntegrityEngine):
                engine.scan_tool_manifest(tools)

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
        from .exceptions import AuthenticationError, AuthorizationError

        for engine in self._engines:
            if self._dry_run:
                try:
                    ctx = await engine.on_request(ctx, req)
                except CoSAIException as exc:
                    # Fix 2: auth errors are NEVER suppressed in dry_run — the
                    # destructive-tool two-stage gate and authentication checks
                    # must fire regardless of dry_run mode.
                    if isinstance(exc, (AuthorizationError, AuthenticationError)):
                        raise
                    log.warning(
                        "CoSAIGuard [dry_run] WOULD HAVE BLOCKED request [%s/%s]: %s",
                        type(engine).__name__,
                        exc.__class__.__name__,
                        exc,
                    )
                    # Audit the dry-run event if an AuditEngine is configured.
                    await self._audit_dry_run(ctx, req, exc)
                    # Do not re-raise — allow request to proceed.
            else:
                ctx = await engine.on_request(ctx, req)
            set_context(ctx)
        return ctx

    async def _run_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        from .exceptions import AuthenticationError, AuthorizationError

        for engine in reversed(self._engines):
            if self._dry_run:
                try:
                    ctx = await engine.on_response(ctx, resp)
                except CoSAIException as exc:
                    # Fix 2: auth errors are NEVER suppressed in dry_run.
                    if isinstance(exc, (AuthorizationError, AuthenticationError)):
                        raise
                    log.warning(
                        "CoSAIGuard [dry_run] WOULD HAVE BLOCKED response [%s/%s]: %s",
                        type(engine).__name__,
                        exc.__class__.__name__,
                        exc,
                    )
                    # Do not re-raise — allow response to proceed.
            else:
                ctx = await engine.on_response(ctx, resp)
            set_context(ctx)
        return ctx

    async def _audit_dry_run(self, ctx: CoSAIContext, req: MCPRequest, exc: CoSAIException) -> None:
        """Write a dry_run-tagged record to AuditEngine if one is present."""
        from .engines.audit import AuditEngine

        for engine in self._engines:
            if isinstance(engine, AuditEngine):
                try:
                    await engine._append(
                        "dry_run_violation",
                        ctx,
                        method=req.method,
                        params_digest="",
                        extra={
                            "dry_run": True,
                            "violation_class": exc.__class__.__name__,
                            "violation_detail": str(exc),
                        },
                    )
                except Exception as exc:
                    # audit failure must not interfere with dry_run pass-through
                    log.warning("dry-run audit write failed (non-fatal): %s", exc)
                break

    def filter_tools_list(self, tool_names: list[str], ctx: CoSAIContext) -> list[str]:
        """Delegate tools/list scope filtering to AuthzEngine (T2-004b).

        Returns only the tool names the caller is authorised to see.  Called by
        adapters after the upstream app returns a tools/list response, before the
        response is forwarded to the client.
        """
        from .engines.authz import AuthzEngine

        for engine in self._engines:
            if isinstance(engine, AuthzEngine):
                return engine.filter_tools_list(tool_names, ctx)
        return tool_names  # no AuthzEngine configured — pass-through

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
        pii_profile: str | None = None,
        required_scope: str | None = None,
        allow_unauthenticated: bool = False,
    ) -> Callable[..., Any]:
        """
        Per-tool decorator that applies a filtered engine subset around a single tool.

        threats:              limit which CoSAI categories run (e.g. ["T3", "T5"]).
                              All engines run when omitted. AuthEngine (T1) and
                              AuthzEngine (T2) always run regardless of threats= filter
                              unless allow_unauthenticated=True.
        pii_profile:          override the T5 PII profile for this tool only
                              ("minimal" | "pci" | "hipaa" | "gdpr" | "strict").
        required_scope:       OAuth scope string that must appear in ctx.scopes for the call
                              to proceed. Raises AuthorizationError if absent.
        allow_unauthenticated: set True ONLY for public/unauthenticated tools. When False
                              (the default), AuthEngine and AuthzEngine always run even if
                              not listed in threats=. This prevents inadvertent auth bypass
                              via threats=["T3"] or similar.

        Usage:
            @app.tool()
            @guard.protect(threats=["T3", "T5"], pii_profile="strict", required_scope="admin")
            async def patient_lookup(mrn: str) -> str: ...
        """
        # --- build the active engine list once at decoration time ---
        if threats is not None:
            unknown = set(threats) - _THREAT_ENGINE_TYPES.keys()
            if unknown:
                raise ValueError(f"Unknown threat codes: {sorted(unknown)!r}")
            engine_types = tuple(_THREAT_ENGINE_TYPES[t] for t in threats)
            active: list[ProtectionEngine] = [
                e for e in self._engines if isinstance(e, engine_types)
            ]
            # Fix 3: AuthEngine (T1) and AuthzEngine (T2) are ALWAYS included
            # regardless of the threats= filter — a developer who writes
            # threats=["T3"] must not accidentally remove authentication.
            if not allow_unauthenticated:
                forced = [
                    e
                    for e in self._engines
                    if isinstance(e, (AuthEngine, AuthzEngine)) and e not in active
                ]
                # Prepend forced engines so auth runs before other engines.
                active = forced + active
        else:
            active = list(self._engines)

        if pii_profile is not None:
            active = [
                PIIEngine(profile=pii_profile) if isinstance(e, PIIEngine) else e for e in active
            ]

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            @functools.wraps(fn)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                from types import MappingProxyType

                from .exceptions import AuthorizationError

                # Fix 2: if an ASGI adapter set the active context ContextVar for
                # this request, use it — it already has real JWT scopes, user_id,
                # tenant_id, etc. from the full auth pipeline.  Fall back to a
                # fresh stdio context when no ASGI request is active (direct
                # stdio calls, tests, or non-HTTP transports).
                asgi_ctx = _active_ctx.get()
                if asgi_ctx is not None:
                    ctx = asgi_ctx
                    req = MCPRequest(
                        method="tools/call",
                        params=MappingProxyType({"name": fn.__name__, "arguments": kwargs}),
                        session_id=ctx.session_id,
                        raw_headers=MappingProxyType({}),
                        transport=ctx.transport,
                    )
                else:
                    # stdio / test path — must be a signature-verifiable token: when
                    # T7 is enabled, SessionEngine.on_request verifies this — a raw
                    # UUID would always raise SessionError and break every decorated tool.
                    session_id = self.mint_session_id("stdio")
                    ctx = CoSAIContext.new(session_id, transport="stdio")
                    req = MCPRequest(
                        method="tools/call",
                        params=MappingProxyType({"name": fn.__name__, "arguments": kwargs}),
                        session_id=session_id,
                        raw_headers=MappingProxyType({}),
                        transport="stdio",
                    )

                for engine in active:
                    ctx = await engine.on_request(ctx, req)
                    set_context(ctx)
                # Per-tool scope enforcement — checked after on_request so AuthEngine
                # has a chance to populate ctx.scopes from request headers.
                if required_scope is not None and required_scope not in ctx.scopes:
                    raise AuthorizationError(
                        f"Tool {fn.__name__!r} requires scope {required_scope!r}"
                    )
                result = await fn(*args, **kwargs)
                # F1 fix: keep an unescaped, entity-decoded copy for detection.
                # Escaping before scanning neutralised the engine's own
                # angle-bracket injection signatures on this path too.
                resp = MCPResponse.from_text(str(result))
                for engine in reversed(active):
                    ctx = await engine.on_response(ctx, resp)
                    set_context(ctx)
                return result

            return wrapper

        return decorator


# Populated after CoSAIGuard is defined so all engine types are importable.
_THREAT_ENGINE_TYPES.update(
    {
        "T1": AuthEngine,
        "T2": AuthzEngine,
        "T3": ValidationEngine,
        "T4": BoundaryEngine,
        "T5": PIIEngine,
        "T6": IntegrityEngine,
        "T7": SessionEngine,
        "T8": NetworkEngine,
        "T9": TrustEngine,
        "T10": ResourceEngine,
        "T11": SupplyChainEngine,
        "T12": AuditEngine,
    }
)
