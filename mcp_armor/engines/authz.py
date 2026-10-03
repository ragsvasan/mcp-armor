"""T2 — Missing Access Control: per-tool RBAC, confused deputy prevention."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import threading
import time
from typing import TYPE_CHECKING

from ..context import CoSAIContext
from ..exceptions import AuthorizationError
from ..types import CONTENT_BEARING_METHODS, MCPRequest, MCPResponse

# MCP control-plane methods that carry no tool/resource invocation and are safe
# to pass through authz (handshake / capability discovery / notifications).
# Anything NOT in this set and NOT a content-bearing method is default-denied
# (fail closed) so a novel or attacker-chosen method name cannot skip the
# authz gate (F2).
#
# Source: the standard methods of the Model Context Protocol specification
# (schema revision 2025-06-18, https://modelcontextprotocol.io/specification/
# 2025-06-18 — `methods` enumerated across the client, server and shared
# schemas). Content-bearing invocations (tools/call, resources/read,
# resources/subscribe, prompts/get) are deliberately NOT listed here — they
# go through full RBAC via CONTENT_BEARING_METHODS. Everything else in the
# spec is a handshake / discovery / lifecycle / notification frame that
# carries no tool or resource invocation and is safe to pass through.
#
# BLOCK[2] fix: the prior list omitted resources/unsubscribe (the documented
# pair of resources/subscribe, which IS a content-bearing method),
# roots/list, sampling/createMessage, elicitation/create, and the
# notifications/* control frames (cancelled, progress, message,
# roots/list_changed). Under the default `default_deny=True` these were
# hard-denied with -32002, silently breaking any deployed MCP server that
# uses subscriptions, progress, cancellation, sampling, elicitation or
# roots. Adding a new standard MCP method in a future protocol revision
# requires extending this set (or CONTENT_BEARING_METHODS for invocations).
_AUTHZ_PASSTHROUGH_METHODS: frozenset[str] = frozenset(
    {
        # Lifecycle / handshake
        "initialize",
        # MCP 2026-07-28 stateless discovery (replaces initialize; no content)
        "server/discover",
        "notifications/initialized",
        "ping",
        # Capability discovery (read-only listings)
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
        "completion/complete",
        "logging/setLevel",
        # Resource subscription teardown — paired with resources/subscribe
        # (which is a CONTENT_BEARING_METHOD). Unsubscribe carries no resource
        # content, only a uri reference to stop notifications for.
        "resources/unsubscribe",
        # Roots (client-exposed filesystem roots) — listing + change notify
        "roots/list",
        "notifications/roots/list_changed",
        # Server-initiated sampling / elicitation requests (LLM/user round-trips,
        # not tool/resource invocations on this server)
        "sampling/createMessage",
        "elicitation/create",
        # Control / progress / log notification frames
        "notifications/cancelled",
        "notifications/progress",
        "notifications/message",
        # Server-initiated list-changed notifications
        "notifications/resources/list_changed",
        "notifications/resources/updated",
        "notifications/tools/list_changed",
        "notifications/prompts/list_changed",
    }
)

if TYPE_CHECKING:
    from ..config import ToolPolicy

log = logging.getLogger(__name__)


class _TokenStore:
    """
    Per-session confirmation token store for the destructive two-stage commit gate.

    Security properties:
    - CSPRNG tokens (256 bits) prevent guessing
    - TTL eviction prevents replay after expiry
    - Constant-time comparison against a fixed-length dummy token prevents timing oracle
      on both the missing-entry and expired-entry paths
    - Tokens are single-use: consumed on first valid check
    - Tokens are keyed by (session_id, tool_name) — prevents cross-tool replay within session

    IMPORTANT: This is an in-process store. It is NOT safe for multi-worker deployments.
    In multi-worker deployments, back this with a shared session store (Redis/DB).
    """

    def __init__(
        self,
        ttl_seconds: int,
        max_entries: int = 10_000,
        max_per_owner: int = 64,
        max_per_principal: int = 256,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        # Two quotas so no caller can fill the global store and starve others'
        # confirmations: per owner (a legacy session, or a stateless principal)
        # and per principal across all of its sessions (opening many sessions
        # does not multiply the allowance; unauthenticated callers share one).
        self._max_per_owner = max_per_owner
        self._max_per_principal = max_per_principal
        # key → (token, expiry_mono, owner, principal)
        self._entries: dict[str, tuple[str, float, str, str]] = {}
        self._lock = threading.Lock()
        # Fixed-length dummy for constant-time compare when no entry / expired entry exists.
        # Must be the same length as issued tokens (token_urlsafe(32) → 43 chars).
        self._dummy: str = secrets.token_urlsafe(32)

    @staticmethod
    def _make_key(session_id: str, tool_name: str) -> str:
        """Bind the token to both session and tool — prevents cross-tool replay."""
        return f"{session_id}::{tool_name}"

    def issue(
        self, session_id: str, tool_name: str, *, owner: str = "", principal: str = ""
    ) -> str:
        """
        Generate a new confirmation token for (session_id, tool_name).

        Replaces any prior pending token for this (session, tool) pair.
        Lazily evicts expired entries on each issue() call.
        """
        token = secrets.token_urlsafe(32)
        expiry = time.monotonic() + self._ttl
        key = self._make_key(session_id, tool_name)
        with self._lock:
            # Lazy eviction — amortised O(1) per call
            now = time.monotonic()
            expired_keys = [k for k, e in self._entries.items() if e[1] <= now]
            for k in expired_keys:
                del self._entries[k]
            # Bindings include an arguments digest, so distinct argument sets
            # create distinct pending entries — bound them and fail closed.
            owner = owner or session_id
            if key not in self._entries and (
                sum(1 for e in self._entries.values() if e[2] == owner) >= self._max_per_owner
                or sum(1 for e in self._entries.values() if e[3] == principal)
                >= self._max_per_principal
            ):
                raise AuthorizationError(
                    "Too many pending destructive-action confirmations for this "
                    "caller — try again after they expire (T2-004)"
                )
            if key not in self._entries and len(self._entries) >= self._max_entries:
                raise AuthorizationError(
                    "Too many pending destructive-action confirmations — try again "
                    "after existing confirmations expire (T2-004)"
                )
            self._entries[key] = (token, expiry, owner, principal)
        return token

    def consume(self, session_id: str, tool_name: str, presented_token: str) -> bool:
        """
        Validate and consume the token.  Returns True on success.

        Uses constant-time comparison against a fixed-length dummy token when no entry
        exists or when the entry has expired — prevents timing oracle attacks that distinguish
        "no entry" from "wrong token".
        """
        key = self._make_key(session_id, tool_name)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                secrets.compare_digest(presented_token, self._dummy)
                return False
            stored_token, expiry = entry[0], entry[1]
            if time.monotonic() > expiry:
                del self._entries[key]
                secrets.compare_digest(presented_token, self._dummy)
                return False
            valid = secrets.compare_digest(stored_token, presented_token)
            if valid:
                del self._entries[key]
            return valid


class AuthzEngine:
    """
    Enforces per-tool scope requirements against the caller's identity.

    Covers:
    - T2-001: Missing per-tool RBAC (required_scopes subset check)
    - T2-002: Confused deputy (server-to-server request executing user-only tool)
    - T2-003: Multi-tenant data bleed (tenant_id isolation — default-deny when absent)
    - T2-004: Destructive one-shot execution (two-stage commit gate, CoSAI CodeGuard T02-003)
    - T2-004b: tools/list manifest scope filtering (cosai-mcp T02-004)

    All decisions are deterministic policy — no LLM judgment in the auth path.

    Scope matching: exact, case-sensitive string comparison against ctx.scopes (set by
    AuthEngine from the JWT `scope` / `scopes` claim). No wildcard expansion. Scope strings
    with embedded whitespace are rejected at AuthEngine ingest.

    Destructive confirmation: confirmation tokens are keyed by (session_id, tool_name)
    and are single-use with a TTL. They are returned in the error message to allow
    the caller to re-submit. NOTE: this mechanism relies on a human reviewing the plan
    before re-submission; an unattended LLM agent will auto-re-submit. For production
    deployments requiring human-in-the-loop, pair with RFC 9470 step-up authentication
    or an out-of-band approval flow.
    """

    def __init__(
        self,
        tool_policies: dict[str, ToolPolicy] | None = None,
        default_deny: bool = True,
        destructive_token_ttl_seconds: int = 60,
        echo_confirm_token: bool = False,
    ) -> None:
        self._policies: dict[str, ToolPolicy] = tool_policies or {}
        self._default_deny = default_deny
        # echo_confirm_token PARADOX — read before changing this default:
        #
        # This setting has an irresolvable security paradox:
        #
        #   echo_confirm_token=False (default): the confirmation token is written
        #   to the server log (WARNING level) and NOT returned in the error body.
        #   Human operators can retrieve it out-of-band and re-submit.  However,
        #   clients that cannot read server logs (most HTTP clients, LLM agents)
        #   have no way to complete the two-stage flow — the gate is effectively
        #   broken for them.
        #
        #   echo_confirm_token=True: the confirmation token IS included in the
        #   JSON-RPC error body returned to the client.  This allows the flow to
        #   complete for any client, BUT autonomous LLM agents that can read their
        #   own error messages will parse the token and auto-resubmit it on the
        #   very next call — fully defeating the human-in-the-loop gate.
        #
        # CONCLUSION: the destructive gate is only meaningful for deployments
        # where the client routes the error through a human approval step before
        # the token is returned to the agent (e.g. a UI "Are you sure?" dialog
        # that intercepts the error before the agent sees it).
        # For fully autonomous agent clients, this gate provides no protection
        # regardless of this setting.  Pair with RFC 9470 step-up authentication
        # or an out-of-band approval workflow for real human-in-the-loop control.
        #
        # See: docs/SECURITY.md § "Destructive Tool Gate — Known Limitations"
        self._echo_confirm_token = echo_confirm_token
        self._token_store = _TokenStore(destructive_token_ttl_seconds)
        log.warning(
            "AuthzEngine: destructive token store is in-process (single-worker only). "
            "For multi-worker deployments, back the token store with a shared backend."
        )

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        # F2 fix: apply RBAC to every content-bearing method, not just
        # tools/call. resources/read & prompts/get reach the upstream server
        # and resolve URIs / templates — they must be authorized too.
        if req.method not in CONTENT_BEARING_METHODS:
            if req.method in _AUTHZ_PASSTHROUGH_METHODS and (
                req.method != "server/discover" or ctx.stateless
            ):
                # server/discover is the 2026-07-28 stateless entry point only;
                # on legacy sessions it stays under default-deny.
                return ctx
            # Fail closed: an unknown method must not bypass the authz gate.
            if self._default_deny:
                raise AuthorizationError(
                    f"Method '{req.method}' is not a recognised MCP method — "
                    "denied (default-deny, T2-001)"
                )
            return ctx

        # Resource subject: tools/call & prompts/get use 'name'; resources/*
        # are keyed by their 'uri'. Policies may be registered under either.
        # tools/call and prompts/get are keyed ONLY by an exact string "name";
        # resources/* only by "uri". Never fall back across them: a request
        # whose real name is hidden from this parser (e.g. "NAME" for a
        # case-insensitive upstream) must not be authorized under its "uri".
        key_field = "uri" if req.method.startswith("resources/") else "name"
        raw_subject = req.params.get(key_field)
        if not isinstance(raw_subject, str) or not raw_subject:
            raise AuthorizationError(
                f"'{req.method}' requires a string '{key_field}' — denied (T2-001)"
            )
        tool_name = raw_subject
        policy = self._policies.get(tool_name)

        # Default deny — tool has no policy entry
        if policy is None:
            if self._default_deny:
                raise AuthorizationError(f"Tool '{tool_name}' not in policy — denied (T2-001)")
            return ctx

        # T2-001: required_scopes subset check — policy.required_scopes ⊆ ctx.scopes
        required = set(policy.required_scopes)
        if required and not required.issubset(set(ctx.scopes)):
            missing = sorted(required - set(ctx.scopes))
            raise AuthorizationError(
                f"Caller lacks required scopes for '{tool_name}': missing {missing} (T2-001)"
            )

        # T2-002: confused deputy — user_only tool called without a user identity.
        # ctx.user_id is set by AuthEngine from the JWT sub claim.
        # No user_id means the request is server-to-server (no user JWT).
        if policy.user_only and not ctx.user_id:
            raise AuthorizationError(
                f"Tool '{tool_name}' is user-only but request has no user identity — "
                "confused deputy attempt rejected (T2-002)"
            )

        # T2-003: multi-tenant isolation — default-deny when argument absent.
        # When tenant_isolated=True the caller MUST supply tenant_id in arguments;
        # omitting it is treated as a policy violation (not a pass-through).
        if policy.tenant_isolated:
            args = req.params.get("arguments", {})
            arg_tenant = args.get("tenant_id") if isinstance(args, dict) else None
            if arg_tenant is None:
                raise AuthorizationError(
                    f"Tool '{tool_name}' requires tenant_id in arguments — "
                    "missing tenant context (T2-003)"
                )
            if arg_tenant != ctx.tenant_id:
                raise AuthorizationError(
                    f"Tool '{tool_name}': argument tenant_id={arg_tenant!r} does not match "
                    f"caller tenant_id={ctx.tenant_id!r} — cross-tenant access denied (T2-003)"
                )

        # T2-004: destructive two-stage commit gate (CoSAI CodeGuard T02-003).
        # Token is keyed by (session_id, tool_name) — prevents cross-tool replay.
        if policy.destructive:
            args = req.params.get("arguments", {})
            confirm_token = args.get("_confirm_token") if isinstance(args, dict) else None
            binding = self._confirm_binding(ctx, tool_name, args)
            if not confirm_token:
                owner = (
                    json.dumps(["stateless", ctx.user_id, ctx.tenant_id])
                    if ctx.stateless
                    else json.dumps(["session", ctx.session_id])
                )
                principal = (
                    json.dumps([ctx.user_id, ctx.tenant_id]) if ctx.user_id else "anonymous"
                )
                token = self._token_store.issue(
                    binding, tool_name, owner=owner, principal=principal
                )
                if self._echo_confirm_token:
                    raise AuthorizationError(
                        f"Tool '{tool_name}' is destructive and requires explicit "
                        f"confirmation. Re-submit with '_confirm_token': '{token}' "
                        f"in the arguments (T2-004). Token is bound to this tool "
                        f"and session only."
                    )
                # F9 fix: deliver the token out-of-band only. The client error
                # carries NO token, so an autonomous agent cannot auto-confirm.
                log.warning(
                    "Destructive tool %r confirmation token issued for session "
                    "%s (out-of-band delivery; not echoed to client): %s",
                    tool_name,
                    ctx.session_id,
                    token,
                )
                raise AuthorizationError(
                    f"Tool '{tool_name}' is destructive and requires explicit "
                    f"out-of-band confirmation (T2-004). A confirmation token has "
                    f"been issued to the operator channel; resubmit with the "
                    f"'_confirm_token' obtained out-of-band. The token is NOT "
                    f"returned in this response by design."
                )
            if not self._token_store.consume(binding, tool_name, str(confirm_token)):
                raise AuthorizationError(
                    f"Tool '{tool_name}': _confirm_token is invalid or expired — "
                    "destructive action denied (T2-004)"
                )

        return ctx

    @staticmethod
    def _confirm_binding(ctx: CoSAIContext, tool_name: str, args: object) -> str:
        """What a destructive-tool confirmation token is bound to.

        Legacy sessions: the session id. Stateless MCP 2026-07-28 requests get a
        fresh internal id per request, so the token is bound instead to the
        authenticated principal + tenant + the exact arguments (minus the token)
        — a confirmed token cannot be replayed by another principal or with
        different, more destructive arguments. Without an authenticated
        principal there is nothing durable to bind to: fail closed.
        """
        clean = (
            {k: v for k, v in args.items() if k != "_confirm_token"}
            if isinstance(args, dict)
            else args
        )
        digest = hashlib.sha256(
            json.dumps(clean, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
        # JSON arrays with an explicit kind tag: a legacy binding can never equal
        # a stateless one (even for an attacker-chosen session id), and both bind
        # the confirmed arguments so an approval cannot be reused for others.
        if not ctx.stateless:
            return json.dumps(["session", ctx.session_id, digest], separators=(",", ":"))
        if not ctx.user_id:
            raise AuthorizationError(
                f"Tool '{tool_name}' is destructive: stateless requests require an "
                "authenticated principal for the two-stage confirmation (T2-004)"
            )
        # Unambiguous (no delimiter collisions between claim values) and
        # distinguishes tenant None from "".
        return json.dumps(["stateless", ctx.user_id, ctx.tenant_id, digest],
                          separators=(",", ":"))

    def filter_tools_list(self, tool_names: list[str], ctx: CoSAIContext) -> list[str]:
        """Return only the tool names the caller is allowed to see (T2-004b).

        A caller must not discover tool names they cannot call — leaking admin,
        purge, or write-scope tool names to read-only callers exposes attack surface.

        Rules:
        - If the tool has no policy entry and default_deny is False → visible.
        - If the tool has no policy entry and default_deny is True → hidden.
        - If the tool has required_scopes the caller lacks → hidden.
        - Otherwise → visible.
        """
        caller_scopes = set(ctx.scopes)
        visible: list[str] = []
        for name in tool_names:
            policy = self._policies.get(name)
            if policy is None:
                if not self._default_deny:
                    visible.append(name)
                # default_deny=True → omit unknown tools from the manifest
                continue
            required = set(policy.required_scopes)
            if required and not required.issubset(caller_scopes):
                continue  # caller lacks scope → hide this tool
            visible.append(name)
        return visible

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
