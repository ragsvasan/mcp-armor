"""mcp-armor sidecar — put any HTTP-transport MCP server behind the 12-engine guard.

A non-Python MCP server (TypeScript, Go, …) cannot import mcp-armor. The sidecar
runs mcp-armor as a thin reverse proxy in front of it: every JSON-RPC request and
response passes through ``ArmorMiddleware`` (all enforcement reused, nothing
re-implemented here) before reaching — or returning from — the upstream server.

    MCP client ──▶ mcp-armor sidecar ──▶ your MCP server
                   (Python, :8000)        (any language, :3000)
                   all engines run        only sees clean traffic

Run it::

    pip install "mcp-armor[sidecar]"
    python -m mcp_armor.sidecar --config cosai.yaml --upstream http://localhost:3000
    # or, via the console script:
    mcp-armor-sidecar --config cosai.yaml --upstream http://localhost:3000

Transport scope — **HTTP only.** ``ArmorMiddleware`` is ASGI middleware; it sits
inline on the HTTP/JSON-RPC path and cannot intercept a stdio pipe. A stdio
upstream is not covered; switch the deployment you want to protect to HTTP
transport, or use a native in-process integration. The HTTP-only boundary is
enforced (non-HTTP ASGI scopes raise ``NotImplementedError``) and tested.

What this module deliberately does NOT include (deployment- or app-specific glue
that belongs in your own outer middleware, not a general-purpose library): IP
rate limiting, cloud-provider detection / structured logging, audit-path
rewriting, framework-specific forwarded-header injection, response recompression,
and path-prefix routing. Compose those around :func:`build_app` if you need them.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import logging
import os
import posixpath
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # avoid importing the optional deps at module import time
    import httpx

from .adapters.fastapi import ArmorMiddleware

log = logging.getLogger(__name__)

Scope = dict[str, Any]
Receive = Callable[..., Any]
Send = Callable[..., Any]

# Default listen address — loopback only. The upstream and the sidecar are meant
# to share a host (or pod); bind to 0.0.0.0 explicitly only when a load balancer
# terminates in front of the sidecar.
_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8000
_DEFAULT_UPSTREAM = "http://localhost:3000"

# Cap on the buffered upstream response body. The upstream is UNTRUSTED (the whole
# reason the response-phase engines exist), so a compromised upstream must not be
# able to OOM the sidecar with a giant body. 10 MiB is generous for JSON-RPC tool
# results; override with --max-response-bytes / ARMOR_MAX_RESPONSE_BYTES.
_DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024

# MCP JSON-RPC over HTTP is POST-only here. GET (SSE streams) and DELETE (session
# termination) are deliberately not proxied — the sidecar buffers full bodies and
# does not cover streaming transports (see module docstring).
_ALLOWED_METHODS = frozenset({"POST"})

# httpx timeouts for the upstream hop. Generous read for slow tools; short connect
# so an unreachable upstream fails fast rather than hanging the client.
_CONNECT_TIMEOUT = 5.0
_READ_TIMEOUT = 30.0
_WRITE_TIMEOUT = 10.0
_POOL_TIMEOUT = 5.0

# Hop-by-hop headers (RFC 7230 §6.1) must not be forwarded by a proxy.
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

# Forwarding-context headers a client must not be allowed to inject — they would
# spoof the upstream's notion of the real caller (IP, host, original URL).
_STRIP_CLIENT_HEADERS = frozenset(
    {
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "x-original-url",
        "x-rewrite-url",
        "forwarded",
    }
)

# MCP §3.4 session header name (mirrored from the fastapi adapter).
_SESSION_HEADER_STR = "mcp-session-id"

# Upstream response headers to drop: httpx already decoded the body, so a stale
# content-encoding makes the client double-decode; content-length is recomputed
# from the bytes we actually send. mcp-session-id is stripped because armor owns
# the session namespace — a (possibly compromised) upstream must never be able to
# set or rotate the client's session id mid-stream (T7 session-fixation / FM-5).
_STRIP_RESPONSE_HEADERS = frozenset({"content-encoding", "content-length", _SESSION_HEADER_STR})

# Headers armor generates / owns that must NOT be forwarded to the upstream. The
# upstream is a separate trust domain; armor's HMAC-signed session id is
# meaningless to it and forwarding it invites a confused-deputy (the upstream
# trusting armor's credential as its own — FM-2 / T9). Armor is the sole session
# authority when deployed as a sidecar; the upstream is stateless w.r.t. MCP
# sessions (it never issued the id the client carries — armor replaced it at
# initialize).
_STRIP_BEFORE_UPSTREAM = frozenset({_SESSION_HEADER_STR})

# Client credential headers dropped before the upstream hop when
# ``strip_upstream_auth`` is enabled. The upstream is a SEPARATE TRUST DOMAIN (see
# ``_STRIP_RESPONSE_HEADERS`` and the module docstring — "a compromised upstream
# must not…"). Forwarding a live ``Authorization``/``Cookie``/``DPoP`` verbatim
# lets a popped upstream harvest and replay the client's bearer token against any
# other service that accepts it (plain bearer tokens are not sender-constrained).
# Stripping is OPT-IN (default off): the common single-trust-domain deployment
# (armor and the upstream co-owned, sharing the credential's trust domain) needs
# the credential to reach the upstream. Enable it only when armor terminates auth
# and the upstream does NOT share that trust domain.
_UPSTREAM_AUTH_HEADERS = frozenset({"authorization", "cookie", "dpop"})


class SidecarDependencyError(RuntimeError):
    """Raised when the optional sidecar dependencies (httpx, uvicorn) are absent."""


def _require_httpx() -> Any:
    try:
        import httpx
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised via monkeypatch test
        raise SidecarDependencyError(
            "The sidecar requires httpx. Install the sidecar extra:\n"
            '    pip install "mcp-armor[sidecar]"'
        ) from exc
    return httpx


def _require_uvicorn() -> Any:
    try:
        import uvicorn
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised via monkeypatch test
        raise SidecarDependencyError(
            "The sidecar requires uvicorn to serve. Install the sidecar extra:\n"
            '    pip install "mcp-armor[sidecar]"'
        ) from exc
    return uvicorn


def _validate_path(path: str) -> str:
    """Normalise and reject dangerous request paths before forwarding upstream.

    Rejects scheme-relative ``//host`` paths, percent-encoded slashes and null
    bytes (traversal/truncation bypasses) and CRLF (request smuggling). Returns
    the ``posixpath.normpath``-normalised path.
    """
    if not path.startswith("/"):
        raise ValueError("path must start with /")
    if path.startswith("//"):
        raise ValueError("scheme-relative path rejected")
    if "\r" in path or "\n" in path:
        raise ValueError("CRLF bytes in path rejected")
    lower = path.lower()
    if "%2f" in lower:
        raise ValueError("percent-encoded slash rejected")
    if "%00" in lower or "\x00" in path:
        raise ValueError("null byte in path rejected")
    return posixpath.normpath(path)


async def _send_json(send: Send, status: int, body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


def _jsonrpc_error(code: int, message: str) -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}}
    ).encode()


class _NoCookieJar(http.cookiejar.CookieJar):
    """Cookie jar that never stores a cookie — a transparent proxy must be stateless.

    httpx's default ``AsyncClient`` keeps a process-scoped cookie jar: it would
    accumulate ``Set-Cookie`` from the upstream and re-inject those cookies on
    later requests, bleeding one MCP session's cookies into another's upstream
    request. Overriding ``set_cookie`` to a no-op is the stdlib-documented
    extension point for ``CookieJar`` subclasses. (The browser owns cookie state;
    the proxy forwards ``Set-Cookie``/``Cookie`` headers verbatim and stores
    nothing.)
    """

    def set_cookie(self, cookie: http.cookiejar.Cookie) -> None:
        pass


class ForwardingApp:
    """ASGI app that reverse-proxies every HTTP request to a single upstream MCP server.

    It is the innermost layer of the sidecar stack; ``ArmorMiddleware`` wraps it,
    buffers the upstream response, and runs the response-phase engines before any
    bytes reach the client. Security posture of the hop itself:

    - ``follow_redirects=False`` and ``trust_env=False`` on the httpx client — a
      malicious or compromised upstream cannot redirect the proxy to an internal
      address (SSRF), and ambient ``HTTP(S)_PROXY`` env vars are ignored.
    - Client-supplied forwarding headers (``X-Forwarded-*``, ``Forwarded``,
      ``X-Real-IP``) are stripped; a single authoritative ``X-Forwarded-For`` with
      the TCP peer is injected so the upstream sees the real caller, not a spoof.
    - Hop-by-hop headers are dropped both ways; request headers are de-duplicated
      by name (first wins) to defeat Content-Type desync; the forwarded
      ``Content-Type`` is overwritten with the canonical ``application/json`` so
      the value the upstream parses is identical to the one the guard validated;
      the client ``Content-Length`` is dropped so httpx reframes the body from
      ``content=`` (a client CL/TE desync cannot smuggle a second request past the
      guard); CRLF in any forwarded header name or value drops that header
      (response splitting / smuggling).
    - With ``strip_upstream_auth=True`` the client credentials
      (``Authorization`` / ``Cookie`` / ``DPoP``) are dropped before the upstream
      hop. Default False preserves the transparent passthrough; enable it only when
      armor terminates auth and the upstream is a DIFFERENT trust domain, so a
      compromised upstream cannot harvest and replay the client's bearer token.
    - Only ``POST`` with a non-empty body is proxied (MCP JSON-RPC over HTTP);
      other methods / empty bodies are refused before the upstream hop so a
      request the engines could not meaningfully inspect never reaches it.
    - ``mcp-session-id`` is never forwarded upstream (armor owns the session
      namespace) and never accepted from the upstream response (it must not
      rotate the client's session).
    - The full upstream body is buffered up to ``max_response_bytes`` (the
      upstream is untrusted); no streaming/SSE — that path is not guarded.
    """

    def __init__(
        self,
        upstream: str,
        *,
        allowed_path_prefix: str | None = None,
        strip_upstream_auth: bool = False,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
        transport: Any = None,
    ) -> None:
        self._upstream = upstream.rstrip("/")
        # Optional path-prefix lockdown: when set, only paths under this prefix are
        # forwarded (so a client with a valid session cannot reach arbitrary
        # non-MCP upstream routes). None = forward any validated path.
        self._allowed_path_prefix = allowed_path_prefix
        if allowed_path_prefix is None:
            # Mirror ArmorMiddleware's CORS-unenforced startup warning: an unset
            # prefix means any request path that passes _validate_path reaches the
            # upstream host, so a client with a valid session can hit non-MCP routes.
            log.warning(
                "ForwardingApp: allowed_path_prefix not configured — path lockdown is "
                "NOT enforced; any request path that passes _validate_path is forwarded "
                "to the upstream host. Set allowed_path_prefix (CLI --mcp-path / env "
                "ARMOR_MCP_PATH), e.g. /api/mcp, to pin the sidecar to the MCP route."
            )
        # Opt-in credential stripping before the upstream hop. Default False keeps
        # the transparent-proxy passthrough the module has always had; True drops
        # Authorization/Cookie/DPoP so a compromised upstream in a DIFFERENT trust
        # domain cannot harvest and replay the client's live bearer token.
        self._strip_upstream_auth = strip_upstream_auth
        self._max_response_bytes = max_response_bytes
        # Optional httpx transport injection — lets tests mount a stub upstream
        # ASGI app without opening a real socket. Production leaves this None.
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    def _new_client(self) -> Any:
        httpx = _require_httpx()
        return httpx.AsyncClient(
            follow_redirects=False,  # never chase redirects — SSRF prevention
            trust_env=False,  # ignore HTTP_PROXY / HTTPS_PROXY env leakage
            cookies=_NoCookieJar(),  # transparent proxy: never store/re-inject cookies
            timeout=httpx.Timeout(
                connect=_CONNECT_TIMEOUT,
                read=_READ_TIMEOUT,
                write=_WRITE_TIMEOUT,
                pool=_POOL_TIMEOUT,
            ),
            transport=self._transport,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(scope, receive, send)
        elif scope["type"] == "http":
            await self._http(scope, receive, send)
        else:
            # HTTP-only boundary (see module docstring). WebSocket/SSE/stdio are
            # not guarded by ArmorMiddleware, so the sidecar refuses them rather
            # than forwarding traffic the engines never inspected.
            raise NotImplementedError(
                f"ForwardingApp does not proxy scope type {scope['type']!r}. "
                "The mcp-armor sidecar covers HTTP transport only."
            )

    async def _lifespan(self, scope: Scope, receive: Receive, send: Send) -> None:
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                self._client = self._new_client()
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                if self._client is not None:
                    await self._client.aclose()
                    self._client = None
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _http(self, scope: Scope, receive: Receive, send: Send) -> None:
        httpx = _require_httpx()
        method = scope.get("method", "POST").upper()

        # MCP JSON-RPC over HTTP is POST-only here. Refusing other methods stops a
        # client with a valid session from reaching the upstream over a verb the
        # engines never meaningfully inspect (e.g. GET /admin).
        if method not in _ALLOWED_METHODS:
            await _send_json(send, 405, _jsonrpc_error(-32600, "Method not allowed"))
            return

        try:
            path = _validate_path(scope.get("path", "/"))
        except ValueError as exc:
            log.warning("Sidecar rejected path: %s (raw=%r)", exc, scope.get("path"))
            await _send_json(send, 400, _jsonrpc_error(-32600, "Invalid request path"))
            return

        # Optional path-prefix lockdown — keep the sidecar pinned to the MCP route.
        if self._allowed_path_prefix is not None and not (
            path == self._allowed_path_prefix
            or path.startswith(self._allowed_path_prefix.rstrip("/") + "/")
        ):
            log.warning("Sidecar rejected out-of-prefix path: %r", path)
            await _send_json(send, 404, _jsonrpc_error(-32600, "Path not found"))
            return

        # Lazy client init — supports being driven without lifespan events
        # (e.g. httpx.ASGITransport in tests, which does not emit lifespan).
        if self._client is None:
            self._client = self._new_client()

        # Drain the request body (ArmorMiddleware replays the buffered body here).
        parts: list[bytes] = []
        more = True
        while more:
            message = await receive()
            parts.append(message.get("body", b""))
            more = message.get("more_body", False)
        body = b"".join(parts)

        # A JSON-RPC request always has a body. An empty body is not a valid call
        # and must not be relayed to the upstream.
        if not body:
            await _send_json(send, 400, _jsonrpc_error(-32600, "Empty request body"))
            return

        client = scope.get("client")
        peer_ip = str(client[0]) if client and isinstance(client, (list, tuple)) else "unknown"

        # Build forwarded request headers: drop hop-by-hop / host / client-injected
        # forwarding headers / armor-owned headers, de-dup by name (first wins),
        # drop any header whose name OR value carries CRLF. Content-Type is dropped
        # here and re-set to the canonical value below so the upstream parses
        # exactly what the guard validated (no last-wins/first-wins desync).
        # Content-Length is dropped for the same reason (H2): httpx recomputes it
        # authoritatively from content=body, so a client Content-Length that
        # disagrees with the framed body (a CL/TE desync) cannot survive to the
        # upstream and smuggle a second, uninspected request past the guard.
        # When strip_upstream_auth is set, the client credentials
        # (Authorization / Cookie / DPoP) are also dropped before the
        # separate-trust-domain hop (M6).
        seen: set[str] = set()
        fwd: list[tuple[bytes, bytes]] = []
        for k_bytes, v_bytes in scope.get("headers", []):
            k = k_bytes.decode("latin-1").lower()
            if (
                k in _HOP_BY_HOP
                or k == "host"
                or k == "content-type"
                or k == "content-length"
                or k in _STRIP_CLIENT_HEADERS
                or k in _STRIP_BEFORE_UPSTREAM
                or (self._strip_upstream_auth and k in _UPSTREAM_AUTH_HEADERS)
            ):
                continue
            v_str = v_bytes.decode("latin-1")
            if "\r" in k or "\n" in k or "\r" in v_str or "\n" in v_str:
                continue
            if k not in seen:
                fwd.append((k_bytes, v_bytes))
                seen.add(k)
        safe_peer = peer_ip.encode("ascii", "replace")
        fwd.append((b"x-forwarded-for", safe_peer))
        fwd.append((b"x-real-ip", safe_peer))
        # Canonical content-type — identical to what ArmorMiddleware validated.
        fwd.append((b"content-type", b"application/json"))

        qs = scope.get("query_string", b"")
        url = f"{self._upstream}{path}"
        if qs:
            qs_str = qs.decode("latin-1")
            if "\r" in qs_str or "\n" in qs_str:
                log.warning("Sidecar rejected CRLF in query string (path=%r)", path)
                await _send_json(send, 400, _jsonrpc_error(-32600, "Invalid request"))
                return
            url += "?" + qs_str

        # Stream the upstream response with a hard byte ceiling. The upstream is
        # untrusted; never trust its Content-Length — enforce on bytes read so a
        # compromised upstream cannot OOM the sidecar with a giant/slow body.
        try:
            async with self._client.stream(
                method=method,
                url=url,
                content=body,
                headers={k.decode("latin-1"): v.decode("latin-1") for k, v in fwd},
            ) as resp:
                chunks: list[bytes] = []
                total = 0
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total > self._max_response_bytes:
                        await resp.aclose()
                        log.error(
                            "Sidecar upstream response exceeded %d bytes",
                            self._max_response_bytes,
                        )
                        await _send_json(
                            send, 502, _jsonrpc_error(-32603, "Upstream response too large")
                        )
                        return
                    chunks.append(chunk)
                out_body = b"".join(chunks)
                resp_headers = [
                    (k.lower().encode("latin-1"), v.encode("latin-1"))
                    for k, v in resp.headers.multi_items()
                    if k.lower() not in _HOP_BY_HOP
                    and k.lower() not in _STRIP_RESPONSE_HEADERS
                    and "\r" not in k
                    and "\n" not in k
                    and "\r" not in v
                    and "\n" not in v
                ]
                status_code = resp.status_code
        except httpx.RequestError as exc:
            log.error("Sidecar upstream unreachable: %s", exc)
            await _send_json(send, 503, _jsonrpc_error(-32603, "Upstream server unavailable"))
            return

        resp_headers.append((b"content-length", str(len(out_body)).encode()))
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": resp_headers,
            }
        )
        await send({"type": "http.response.body", "body": out_body, "more_body": False})


def build_app(
    upstream: str = _DEFAULT_UPSTREAM,
    *,
    guard: Any = None,
    config_path: str | Path | None = None,
    cors_origins: list[str] | None = None,
    max_body_bytes: int | None = None,
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
    allowed_path_prefix: str | None = None,
    strip_upstream_auth: bool = False,
    transport: Any = None,
) -> ArmorMiddleware:
    """Assemble the sidecar ASGI stack: ``ArmorMiddleware(ForwardingApp(upstream), guard)``.

    Exactly one of ``guard`` or ``config_path`` must identify the guard:

    - ``guard``       — a pre-built :class:`~mcp_armor.guard.CoSAIGuard` (used by tests
                        and by callers composing their own engine set).
    - ``config_path`` — path to a ``cosai.yaml``; the guard is built via
                        :meth:`CoSAIGuard.from_config`.

    ``cors_origins`` is forwarded to ``ArmorMiddleware`` (T7-001). Pass ``[]`` to
    block all cross-origin requests, or an explicit allowlist. ``max_response_bytes``
    caps the buffered (untrusted) upstream body. ``allowed_path_prefix`` pins the
    sidecar to a single MCP route (a startup warning is logged when it is None).
    ``strip_upstream_auth`` drops the client ``Authorization``/``Cookie``/``DPoP``
    before the upstream hop — enable it only when armor terminates auth and the
    upstream is a different trust domain (default False forwards the credential, so
    the upstream must share the credential's trust domain). ``transport`` is an
    optional httpx transport for the upstream hop (test seam only).
    """
    if guard is None and config_path is None:
        raise ValueError("build_app requires either a guard or a config_path")
    if guard is not None and config_path is not None:
        raise ValueError("build_app accepts only one of guard or config_path, not both")

    if guard is None:
        from .guard import CoSAIGuard

        guard = CoSAIGuard.from_config(config_path)  # type: ignore[arg-type]

    forwarder = ForwardingApp(
        upstream,
        allowed_path_prefix=allowed_path_prefix,
        strip_upstream_auth=strip_upstream_auth,
        max_response_bytes=max_response_bytes,
        transport=transport,
    )
    mw_kwargs: dict[str, Any] = {
        "cors_origins": cors_origins,
        # Align the middleware's response ceiling with the forwarder's so a
        # legitimate large tool result isn't rejected at the middleware before
        # the forwarder's own streaming cap even applies.
        "max_response_bytes": max_response_bytes,
    }
    if max_body_bytes is not None:
        mw_kwargs["max_body_bytes"] = max_body_bytes
    return ArmorMiddleware(forwarder, guard, **mw_kwargs)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="mcp-armor-sidecar",
        description="Run mcp-armor as a reverse-proxy sidecar in front of an HTTP MCP server.",
    )
    parser.add_argument(
        "-c",
        "--config",
        default=os.environ.get("ARMOR_CONFIG", "cosai.yaml"),
        help="Path to cosai.yaml (env: ARMOR_CONFIG; default: cosai.yaml).",
    )
    parser.add_argument(
        "-u",
        "--upstream",
        default=os.environ.get("ARMOR_UPSTREAM", _DEFAULT_UPSTREAM),
        help=f"Upstream MCP server URL (env: ARMOR_UPSTREAM; default: {_DEFAULT_UPSTREAM}).",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("ARMOR_SIDECAR_HOST", _DEFAULT_HOST),
        help=f"Listen host (env: ARMOR_SIDECAR_HOST; default: {_DEFAULT_HOST}).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("ARMOR_SIDECAR_PORT", str(_DEFAULT_PORT))),
        help=f"Listen port (env: ARMOR_SIDECAR_PORT; default: {_DEFAULT_PORT}).",
    )
    parser.add_argument(
        "--cors-origin",
        action="append",
        dest="cors_origins",
        default=None,
        help=(
            "Allowed CORS origin (repeatable). If omitted, ARMOR_CORS_ORIGINS "
            "(comma-separated) is used. Pass no origins to leave CORS unenforced "
            "(a startup warning is emitted)."
        ),
    )
    parser.add_argument(
        "--max-body-bytes",
        type=int,
        default=(
            int(os.environ["ARMOR_MAX_BODY_BYTES"])
            if os.environ.get("ARMOR_MAX_BODY_BYTES")
            else None
        ),
        help="Maximum request body size in bytes (env: ARMOR_MAX_BODY_BYTES).",
    )
    parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=int(os.environ.get("ARMOR_MAX_RESPONSE_BYTES", str(_DEFAULT_MAX_RESPONSE_BYTES))),
        help=(
            "Maximum buffered upstream response size in bytes "
            f"(env: ARMOR_MAX_RESPONSE_BYTES; default: {_DEFAULT_MAX_RESPONSE_BYTES})."
        ),
    )
    parser.add_argument(
        "--mcp-path",
        dest="mcp_path",
        default=os.environ.get("ARMOR_MCP_PATH") or None,
        help=(
            "Restrict forwarding to this path prefix, e.g. /api/mcp "
            "(env: ARMOR_MCP_PATH; default: forward any validated path — a startup "
            "warning is emitted when unset)."
        ),
    )
    parser.add_argument(
        "--strip-upstream-auth",
        dest="strip_upstream_auth",
        action="store_true",
        default=os.environ.get("ARMOR_STRIP_UPSTREAM_AUTH", "").strip().lower()
        in ("1", "true", "yes", "on"),
        help=(
            "Strip the client Authorization/Cookie/DPoP headers before forwarding "
            "to the upstream (env: ARMOR_STRIP_UPSTREAM_AUTH). Enable when armor "
            "terminates auth and the upstream is a DIFFERENT trust domain, so a "
            "compromised upstream cannot harvest and replay client bearer tokens. "
            "Default: off — credentials pass through, so the upstream must share "
            "the credential's trust domain."
        ),
    )
    return parser.parse_args(argv)


def _resolve_cors_origins(args: argparse.Namespace) -> list[str] | None:
    if args.cors_origins is not None:
        return list(args.cors_origins)
    raw = os.environ.get("ARMOR_CORS_ORIGINS")
    if raw is None:
        return None
    return [o.strip() for o in raw.split(",") if o.strip()]


def main(argv: list[str] | None = None) -> None:
    """CLI entry point — ``python -m mcp_armor.sidecar`` / ``mcp-armor-sidecar``."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = _parse_args(argv)
    uvicorn = _require_uvicorn()  # fail fast with a clear message if the extra is missing

    cors_origins = _resolve_cors_origins(args)
    app = build_app(
        upstream=args.upstream,
        config_path=args.config,
        cors_origins=cors_origins,
        max_body_bytes=args.max_body_bytes,
        max_response_bytes=args.max_response_bytes,
        allowed_path_prefix=args.mcp_path,
        strip_upstream_auth=args.strip_upstream_auth,
    )
    log.info(
        "mcp-armor sidecar listening on %s:%d → upstream %s (config: %s)",
        args.host,
        args.port,
        args.upstream,
        args.config,
    )
    # lifespan="on" so the guard's startup()/shutdown() and the forwarder's httpx
    # client lifecycle run (ArmorMiddleware drives both through lifespan events).
    uvicorn.run(app, host=args.host, port=args.port, lifespan="on")


if __name__ == "__main__":
    main()
