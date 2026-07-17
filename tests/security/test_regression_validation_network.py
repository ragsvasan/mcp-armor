"""Security regression tests for the 2026-07-17 audit — findings M2 & M3.

M2 (``engines/validation.py``): with ``strict_schema=True`` the optional
``jsonschema`` package is load-bearing for T3-005 enforcement. If it is absent
the old ``_validate_schema`` silently ``return``ed, skipping schema validation
for every ``tools/call`` with no error and no log — a silent security
downgrade. Enforcement now fails CLOSED at startup (and refuses to degrade to a
no-op at request time).

M3 (``engines/network.py``): ``is_ssrf_target`` used to ``return False`` (allow)
when the guard could not resolve a host, and rejected every alternate numeric
IPv4 encoding (decimal/octal/hex/short) as "not an IP". Both let an internal
target through: an unresolvable name a downstream fetcher can still reach
(split-horizon DNS / ``/etc/hosts`` / rebinding), or ``2130706433`` /
``0x7f000001`` / ``127.1`` that ``inet_aton`` expands to 127.0.0.1. It now fails
CLOSED on resolution failure and normalizes numeric encodings to dotted-quad
before the resolve.
"""

from __future__ import annotations

import socket
import sys
from unittest.mock import patch

import pytest

from mcp_armor.config import ConfigError
from mcp_armor.engines.network import NetworkEngine
from mcp_armor.engines.validation import ValidationEngine
from mcp_armor.exceptions import NetworkBindingError
from tests.conftest import make_ctx, make_request

# ---------------------------------------------------------------------------
# M2 — strict_schema must fail closed without jsonschema
# ---------------------------------------------------------------------------


async def test_regression_strict_schema_fails_closed_without_jsonschema(monkeypatch):
    """on_startup must raise ConfigError when strict_schema=True but jsonschema
    is not importable — never boot with T3-005 schema validation silently off.

    ``sys.modules['jsonschema'] = None`` makes ``import jsonschema`` raise
    ImportError even though the package is installed in the test env.
    """
    monkeypatch.setitem(sys.modules, "jsonschema", None)
    engine = ValidationEngine(strict_schema=True)
    with pytest.raises(ConfigError, match="jsonschema"):
        await engine.on_startup()


async def test_strict_schema_startup_ok_with_jsonschema():
    """Positive control: with jsonschema present, strict startup does not raise."""
    engine = ValidationEngine(strict_schema=True)
    await engine.on_startup()  # must not raise


async def test_non_strict_schema_startup_ok_without_jsonschema(monkeypatch):
    """strict_schema=False does not depend on jsonschema — startup stays clean
    even when the package is unavailable (no over-eager fail-closed)."""
    monkeypatch.setitem(sys.modules, "jsonschema", None)
    engine = ValidationEngine(strict_schema=False)
    await engine.on_startup()  # must not raise


def test_regression_validate_schema_runtime_never_silently_skips(monkeypatch):
    """Belt-and-suspenders for M2: even post-startup, _validate_schema must not
    degrade to a no-op if jsonschema becomes unimportable while strict_schema is
    on — it raises instead of silently returning (which would pass malformed
    arguments the schema should reject)."""
    monkeypatch.setitem(sys.modules, "jsonschema", None)
    engine = ValidationEngine(strict_schema=True)
    with pytest.raises(ConfigError, match="jsonschema"):
        engine._validate_schema({"x": 1}, {"type": "object"}, "some_tool")


# ---------------------------------------------------------------------------
# M3 — SSRF must fail closed when a host cannot be resolved
# ---------------------------------------------------------------------------


def test_regression_ssrf_fails_closed_on_unresolvable_host():
    """A host the guard's resolver cannot resolve must be treated as an SSRF
    target (True) when block_rfc1918_ssrf is on — was fail-open (False)."""
    eng = NetworkEngine(block_rfc1918_ssrf=True)
    with patch(
        "mcp_armor.engines.network.socket.getaddrinfo",
        side_effect=socket.gaierror("nxdomain"),
    ):
        assert eng.is_ssrf_target("nonexistent.invalid") is True


async def test_regression_ssrf_unresolvable_host_blocked_at_on_request():
    """M3 at the public entry point: on_request must reject a tools/call whose
    argument URL has an unresolvable host (the gate fires, not just the helper)."""
    eng = NetworkEngine(block_rfc1918_ssrf=True)
    ctx = make_ctx()
    req = make_request(
        method="tools/call",
        params={"name": "fetch", "arguments": {"url": "http://nonexistent.invalid/x"}},
    )
    with patch(
        "mcp_armor.engines.network.socket.getaddrinfo",
        side_effect=socket.gaierror("nxdomain"),
    ):
        with pytest.raises(NetworkBindingError, match="SSRF target"):
            await eng.on_request(ctx, req)


def test_ssrf_disabled_does_not_overblock_unresolvable_host():
    """Control: with block_rfc1918_ssrf=False the fail-closed rule must not fire
    — SSRF vetting is disabled entirely, so an unresolvable host is allowed."""
    eng = NetworkEngine(block_rfc1918_ssrf=False)
    with patch(
        "mcp_armor.engines.network.socket.getaddrinfo",
        side_effect=socket.gaierror("nxdomain"),
    ):
        assert eng.is_ssrf_target("nonexistent.invalid") is False


# ---------------------------------------------------------------------------
# M3 — numeric IPv4 encodings normalized to dotted-quad before the resolve
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "encoding",
    [
        "2130706433",  # decimal 127.0.0.1
        "017700000001",  # octal   127.0.0.1
        "0x7f000001",  # hex     127.0.0.1
        "127.1",  # short   127.0.0.1 (1 fills the low 3 octets)
        "127.0.1",  # short   127.0.0.1 (1 fills the low 2 octets)
        "167772161",  # decimal 10.0.0.1  (RFC1918)
        "0xA000001",  # hex     10.0.0.1  (RFC1918)
    ],
)
def test_regression_ssrf_blocks_numeric_ipv4_encodings(encoding):
    """Alternate numeric encodings of an INTERNAL address must normalize to
    dotted-quad and block as a literal. getaddrinfo is forced to raise, so a
    True result can ONLY come from the literal-normalization path — proving no
    DNS fall-through (which now also fails closed) is masking a normalization
    gap."""
    eng = NetworkEngine(block_rfc1918_ssrf=True)
    with patch(
        "mcp_armor.engines.network.socket.getaddrinfo",
        side_effect=socket.gaierror("must not be reached"),
    ) as gai:
        assert eng.is_ssrf_target(encoding) is True
    gai.assert_not_called()


@pytest.mark.parametrize(
    "encoding",
    [
        "134744072",  # decimal 8.8.8.8 (public)
        "0x08080808",  # hex     8.8.8.8 (public)
    ],
)
def test_public_numeric_ipv4_encoding_not_blocked(encoding):
    """Complement to the block test: a PUBLIC numeric encoding must normalize to
    its dotted-quad and be ALLOWED (False). With getaddrinfo raising, a False
    result proves normalization resolved it as a literal rather than the
    fail-closed resolve swallowing it (which would wrongly return True)."""
    eng = NetworkEngine(block_rfc1918_ssrf=True)
    with patch(
        "mcp_armor.engines.network.socket.getaddrinfo",
        side_effect=socket.gaierror("must not be reached"),
    ) as gai:
        assert eng.is_ssrf_target(encoding) is False
    gai.assert_not_called()
