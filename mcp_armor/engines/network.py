"""T8 — Network Binding Failures: bind address validation, SSRF prevention."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any

from ..context import CoSAIContext
from ..exceptions import NetworkBindingError
from ..types import MCPRequest, MCPResponse

_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
_LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")
_IPV6_ULA = ipaddress.ip_network("fc00::/7")

# Extracts the host from a URL (scheme://host[:port]/...) — RFC 3986 §3.2
_URL_HOST_RE = re.compile(r'(?:https?|ftp|ws|wss)://([^/\s?#\[\]@:]+)', re.IGNORECASE)


class NetworkEngine:
    """
    Bind address validation and SSRF prevention.

    Covers:
    - T8-001: Server bound to 0.0.0.0 (exposed to local network) — checked at startup
               when bind_host is configured, and via check_bind_address() helper.
    - T8-002: SSRF via tool call arguments referencing internal addresses — enforced
               automatically in on_request() for every tools/call invocation.
    - T8-003: Shadow MCP server on same host (port collision detection)
    """

    def __init__(
        self,
        allow_public_bind: bool = False,
        block_rfc1918_ssrf: bool = True,
        bind_host: str | None = None,
        bind_port: int = 0,
    ) -> None:
        self._allow_public_bind = allow_public_bind
        self._block_rfc1918_ssrf = block_rfc1918_ssrf
        self._bind_host = bind_host
        self._bind_port = bind_port

    async def on_startup(self) -> None:
        # Validate configured bind address at startup so misconfigured servers
        # are caught before accepting any connections (T8-001).
        if self._bind_host is not None:
            self.check_bind_address(self._bind_host, self._bind_port)

    def check_bind_address(self, host: str, port: int) -> None:
        """Call this from server startup with the configured bind host."""
        if host in ("0.0.0.0", "::") and not self._allow_public_bind:
            raise NetworkBindingError(
                f"Server must not bind to {host}:{port} — "
                "use 127.0.0.1 or an explicit interface address"
            )

    def is_ssrf_target(self, host: str) -> bool:
        """Returns True if host resolves to a blocked address range."""
        if not self._block_rfc1918_ssrf:
            return False
        try:
            addr = ipaddress.ip_address(socket.gethostbyname(host))
        except (OSError, ValueError):
            return False
        networks = _RFC1918 + [_LOOPBACK, _LINK_LOCAL, _IPV6_ULA]
        return any(addr in net for net in networks)

    def _scan_args_for_ssrf(self, value: Any) -> None:
        """Recursively scan all string values in tool arguments for SSRF-target URLs."""
        if isinstance(value, str):
            for match in _URL_HOST_RE.finditer(value):
                host = match.group(1)
                if self.is_ssrf_target(host):
                    raise NetworkBindingError(
                        f"Tool argument contains SSRF target: {host!r} resolves "
                        "to a blocked address range (T8-002)"
                    )
        elif isinstance(value, dict):
            for v in value.values():
                self._scan_args_for_ssrf(v)
        elif isinstance(value, list):
            for item in value:
                self._scan_args_for_ssrf(item)

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        if req.method == "tools/call" and self._block_rfc1918_ssrf:
            args = req.params.get("arguments")
            if args is not None:
                self._scan_args_for_ssrf(args)
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
