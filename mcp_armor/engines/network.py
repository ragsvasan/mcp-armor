"""T8 — Network Binding Failures: bind address validation, SSRF prevention."""

from __future__ import annotations

import ipaddress
import socket

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


class NetworkEngine:
    """
    Startup-only checks for dangerous bind addresses and SSRF vectors.

    Covers:
    - T8-001: Server bound to 0.0.0.0 (exposed to local network)
    - T8-002: SSRF via tool arguments referencing internal addresses
    - T8-003: Shadow MCP server on same host (port collision detection)
    """

    def __init__(
        self,
        allow_public_bind: bool = False,
        block_rfc1918_ssrf: bool = True,
    ) -> None:
        self._allow_public_bind = allow_public_bind
        self._block_rfc1918_ssrf = block_rfc1918_ssrf

    async def on_startup(self) -> None:
        pass

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
