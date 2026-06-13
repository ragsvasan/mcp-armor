"""T8 — Network Binding Failures: bind address validation, SSRF prevention."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlsplit

from ..context import CoSAIContext
from ..exceptions import NetworkBindingError
from ..types import MCPRequest, MCPResponse, scannable_strings

_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
_LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")
_IPV6_ULA = ipaddress.ip_network("fc00::/7")
# F3: IPv6 loopback (::1), link-local (fe80::/10), unspecified, and the
# IPv4-mapped/cloud-metadata addresses were not blocked. Cover them all.
_IPV6_LOOPBACK = ipaddress.ip_network("::1/128")
_IPV6_LINK_LOCAL = ipaddress.ip_network("fe80::/10")
_IPV6_UNSPEC = ipaddress.ip_network("::/128")
_CLOUD_METADATA = ipaddress.ip_network("169.254.169.254/32")
_BLOCKED_NETWORKS = _RFC1918 + [
    _LOOPBACK,
    _LINK_LOCAL,
    _IPV6_ULA,
    _IPV6_LOOPBACK,
    _IPV6_LINK_LOCAL,
    _IPV6_UNSPEC,
    _CLOUD_METADATA,
]

# F3: any scheme that can reference a network host is in scope for SSRF —
# not just http/ftp/ws. Schemes that take an authority are scanned via
# urlsplit; schemes that embed a host without an authority (no //) are
# explicitly blocked because they cannot be safely host-resolved here.
_HOST_SCHEMES: frozenset[str] = frozenset(
    {
        "http",
        "https",
        "ftp",
        "ftps",
        "ws",
        "wss",
        "gopher",
        "redis",
        "rediss",
        "mongodb",
        "mysql",
        "postgres",
        "postgresql",
        "ldap",
        "ldaps",
        "memcached",
        "amqp",
        "smb",
        "ssh",
        "sftp",
        "tftp",
    }
)
# Schemes with no network authority that are dangerous as fetch targets
# (local file / process / data exfiltration vectors). Always rejected.
_DENIED_SCHEMES: frozenset[str] = frozenset(
    {
        "file",
        "dict",
        "jar",
        "netdoc",
        "expect",
        "data",
        "php",
        "phar",
        "glob",
    }
)

# Coarse pre-filter: find anything that looks like a URI (scheme:rest) so we
# can hand each candidate to urlsplit. Bracketed IPv6 literals are preserved.
_URI_CANDIDATE_RE = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.\-]*):(//)?\S+")


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
        """Call this from server startup with the configured bind host.

        Rejects any unspecified/wildcard address (binds to all interfaces) unless
        allow_public_bind. A naive string compare against ("0.0.0.0", "::") missed
        equivalent spellings — `[::]` (the common bracketed config form), `::0`,
        `0:0:0:0:0:0:0:0` — so we parse with `ipaddress` and test `is_unspecified`.
        """
        if self._allow_public_bind:
            return
        candidate = host.strip()
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        try:
            addr = ipaddress.ip_address(candidate)
            # An IPv4-mapped IPv6 unspecified (::ffff:0.0.0.0) must be judged as
            # its IPv4 form, otherwise it slips past is_unspecified.
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
                addr = addr.ipv4_mapped
            is_wildcard = addr.is_unspecified
        except ValueError:
            # Not an IP literal. socket treats bare "0" / "" as 0.0.0.0 (all
            # interfaces); a hostname is left for the OS to resolve (not our gate).
            is_wildcard = candidate in ("0", "")
        if is_wildcard:
            raise NetworkBindingError(
                f"Server must not bind to {host}:{port} (all interfaces) — "
                "use 127.0.0.1 or an explicit interface address"
            )

    @staticmethod
    def _addr_is_blocked(addr: ipaddress._BaseAddress) -> bool:
        # IPv4-mapped IPv6 (::ffff:127.0.0.1) must be evaluated as its IPv4
        # form, otherwise loopback/RFC1918 mapped addresses slip through (F3).
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        return any(addr in net for net in _BLOCKED_NETWORKS)

    def is_ssrf_target(self, host: str) -> bool:
        """
        Returns True if host is — or resolves to — a blocked address range.

        F3 fix:
        - strips IPv6 brackets ([::1] -> ::1) before parsing;
        - treats IP literals directly without a DNS round-trip;
        - resolves BOTH A and AAAA records (getaddrinfo) so an IPv6-only or
          dual-stack internal name cannot evade an IPv4-only lookup;
        - blocks if ANY resolved address is internal (fail closed).
        Note: DNS-rebinding TOCTOU is documented as residual risk — true
        closure requires pinned-IP egress at the fetch layer.
        """
        if not self._block_rfc1918_ssrf:
            return False
        host = host.strip()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        # Direct IP literal — no DNS needed.
        try:
            return self._addr_is_blocked(ipaddress.ip_address(host))
        except ValueError:
            pass
        # Hostname — resolve all address families. Fail closed on any blocked.
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except (OSError, UnicodeError):
            return False
        for info in infos:
            sockaddr = info[4]
            try:
                addr = ipaddress.ip_address(sockaddr[0])
            except ValueError:
                continue
            if self._addr_is_blocked(addr):
                return True
        return False

    def _scan_args_for_ssrf(self, value: Any) -> None:
        """
        Recursively scan all string values for SSRF-target URIs.

        F3 fix: parse with urlsplit (bracket-aware), cover every host-bearing
        scheme, and reject authority-less dangerous schemes (file:, dict:,
        data:, gopher: without authority, etc.) outright.
        """
        if isinstance(value, str):
            for m in _URI_CANDIDATE_RE.finditer(value):
                scheme = m.group(1).lower()
                candidate = m.group(0)
                if scheme in _DENIED_SCHEMES:
                    raise NetworkBindingError(
                        f"Tool argument references disallowed scheme {scheme!r} — "
                        "non-network/local schemes are blocked (T8-002)"
                    )
                if scheme not in _HOST_SCHEMES:
                    continue
                try:
                    parts = urlsplit(candidate)
                    host = parts.hostname  # urlsplit strips IPv6 brackets
                except ValueError as exc:
                    # Unparseable authority on a host-scheme — fail closed.
                    raise NetworkBindingError(
                        f"Tool argument contains an unparseable {scheme!r} URL — rejected (T8-002)"
                    ) from exc
                if not host:
                    # gopher://, redis:// etc. with no host we can vet — fail closed.
                    raise NetworkBindingError(
                        f"Tool argument {scheme!r} URL has no resolvable host — rejected (T8-002)"
                    )
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
        # F2 fix: SSRF-scan every content-bearing method. resources/read.uri
        # (e.g. http://[::1]/admin) was previously never SSRF-checked.
        if not self._block_rfc1918_ssrf:
            return ctx
        fields = scannable_strings(req)
        if not fields:
            return ctx
        if "arguments" in fields:
            self._scan_args_for_ssrf(fields["arguments"])
        if "uri" in fields:
            self._scan_args_for_ssrf(fields["uri"])
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
