"""Tests for T8 NetworkEngine — bind address validation, SSRF detection."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mcp_armor.engines.network import NetworkEngine
from mcp_armor.exceptions import NetworkBindingError
from tests.conftest import make_ctx, make_request, make_response


def _engine(**kwargs) -> NetworkEngine:
    defaults = dict(allow_public_bind=False, block_rfc1918_ssrf=True)
    defaults.update(kwargs)
    return NetworkEngine(**defaults)


# ---------------------------------------------------------------------------
# T8-001: bind address validation
# ---------------------------------------------------------------------------

def test_wildcard_bind_rejected() -> None:
    eng = _engine()
    with pytest.raises(NetworkBindingError, match="0.0.0.0"):
        eng.check_bind_address("0.0.0.0", 8080)


def test_ipv6_wildcard_bind_rejected() -> None:
    eng = _engine()
    with pytest.raises(NetworkBindingError, match="::"):
        eng.check_bind_address("::", 8080)


def test_localhost_bind_allowed() -> None:
    eng = _engine()
    eng.check_bind_address("127.0.0.1", 8080)  # must not raise


def test_explicit_interface_allowed() -> None:
    eng = _engine()
    eng.check_bind_address("192.168.1.10", 8080)  # must not raise


def test_allow_public_bind_flag_overrides() -> None:
    eng = _engine(allow_public_bind=True)
    eng.check_bind_address("0.0.0.0", 8080)  # must not raise


# ---------------------------------------------------------------------------
# T8-002: SSRF detection
# ---------------------------------------------------------------------------

def test_loopback_is_ssrf_target() -> None:
    eng = _engine()
    with patch("mcp_armor.engines.network.socket.gethostbyname", return_value="127.0.0.1"):
        assert eng.is_ssrf_target("localhost") is True


def test_rfc1918_10_is_ssrf_target() -> None:
    eng = _engine()
    with patch("mcp_armor.engines.network.socket.gethostbyname", return_value="10.0.1.5"):
        assert eng.is_ssrf_target("internal-host") is True


def test_rfc1918_172_is_ssrf_target() -> None:
    eng = _engine()
    with patch("mcp_armor.engines.network.socket.gethostbyname", return_value="172.16.5.1"):
        assert eng.is_ssrf_target("host") is True


def test_rfc1918_192_168_is_ssrf_target() -> None:
    eng = _engine()
    with patch("mcp_armor.engines.network.socket.gethostbyname", return_value="192.168.0.1"):
        assert eng.is_ssrf_target("host") is True


def test_link_local_is_ssrf_target() -> None:
    eng = _engine()
    with patch("mcp_armor.engines.network.socket.gethostbyname", return_value="169.254.169.254"):
        assert eng.is_ssrf_target("metadata") is True


def test_public_ip_not_ssrf_target() -> None:
    eng = _engine()
    with patch("mcp_armor.engines.network.socket.gethostbyname", return_value="8.8.8.8"):
        assert eng.is_ssrf_target("dns.google") is False


def test_dns_error_returns_false_not_raises() -> None:
    eng = _engine()
    import socket
    with patch("mcp_armor.engines.network.socket.gethostbyname",
               side_effect=socket.gaierror("nxdomain")):
        assert eng.is_ssrf_target("nonexistent.invalid") is False


def test_block_rfc1918_disabled_always_false() -> None:
    eng = _engine(block_rfc1918_ssrf=False)
    # Even loopback — check is disabled
    with patch("mcp_armor.engines.network.socket.gethostbyname", return_value="127.0.0.1"):
        assert eng.is_ssrf_target("localhost") is False


# ---------------------------------------------------------------------------
# Lifecycle hooks (pass-throughs)
# ---------------------------------------------------------------------------

async def test_on_request_passthrough() -> None:
    eng = _engine()
    ctx = make_ctx()
    req = make_request()
    result = await eng.on_request(ctx, req)
    assert result is ctx


async def test_on_response_passthrough() -> None:
    eng = _engine()
    resp = make_response("ok")
    result = await eng.on_response(make_ctx(), resp)
    assert result is not None


async def test_on_startup_passthrough() -> None:
    eng = _engine()
    await eng.on_startup()  # must not raise
