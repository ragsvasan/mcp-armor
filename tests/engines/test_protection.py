"""Tests for T5 ProtectionEngine — PII scrubbing by profile."""

from __future__ import annotations

import pytest

from mcp_armor.engines.protection import ProtectionEngine
from mcp_armor.exceptions import PIILeakError
from tests.conftest import make_ctx, make_response


def _eng(profile: str = "strict") -> ProtectionEngine:
    return ProtectionEngine(profile=profile)


# ---------------------------------------------------------------------------
# PCI profile — SSN, credit card, JWT, API key
# ---------------------------------------------------------------------------


async def test_ssn_in_response_blocked_pci() -> None:
    eng = _eng(profile="pci")
    resp = make_response("Your SSN is 123-45-6789")
    with pytest.raises(PIILeakError, match="ssn"):
        await eng.on_response(make_ctx(), resp)


async def test_credit_card_in_response_blocked_pci() -> None:
    eng = _eng(profile="pci")
    resp = make_response("Card: 4111111111111111")
    with pytest.raises(PIILeakError, match="credit_card"):
        await eng.on_response(make_ctx(), resp)


async def test_jwt_in_response_blocked_pci() -> None:
    eng = _eng(profile="pci")
    # A realistic JWT-shaped token
    token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.fakesignaturevalue12345"
    resp = make_response(f"Token: {token}")
    with pytest.raises(PIILeakError, match="jwt"):
        await eng.on_response(make_ctx(), resp)


async def test_api_key_in_response_blocked_pci() -> None:
    eng = _eng(profile="pci")
    resp = make_response("api_key: abcdefghijklmnop1234")
    with pytest.raises(PIILeakError, match="api_key"):
        await eng.on_response(make_ctx(), resp)


# ---------------------------------------------------------------------------
# HIPAA/GDPR/strict profiles — email, phone also blocked
# ---------------------------------------------------------------------------


async def test_email_in_response_blocked_strict() -> None:
    eng = _eng(profile="strict")
    resp = make_response("Contact: alice@example.com")
    with pytest.raises(PIILeakError, match="email"):
        await eng.on_response(make_ctx(), resp)


async def test_phone_in_response_blocked_strict() -> None:
    eng = _eng(profile="strict")
    resp = make_response("Call: 555-867-5309")
    with pytest.raises(PIILeakError, match="phone"):
        await eng.on_response(make_ctx(), resp)


# ---------------------------------------------------------------------------
# Minimal profile — only JWT and API key
# ---------------------------------------------------------------------------


async def test_email_passes_minimal_profile() -> None:
    eng = _eng(profile="minimal")
    resp = make_response("Contact: alice@example.com")
    result = await eng.on_response(make_ctx(), resp)
    assert result is not None


async def test_ssn_passes_minimal_profile() -> None:
    eng = _eng(profile="minimal")
    resp = make_response("SSN: 123-45-6789")
    result = await eng.on_response(make_ctx(), resp)
    assert result is not None


async def test_jwt_blocked_minimal_profile() -> None:
    eng = _eng(profile="minimal")
    token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.fakesignaturevalue12345"
    resp = make_response(f"token={token}")
    with pytest.raises(PIILeakError, match="jwt"):
        await eng.on_response(make_ctx(), resp)


# ---------------------------------------------------------------------------
# Empty / unknown profile
# ---------------------------------------------------------------------------


async def test_empty_response_passes() -> None:
    eng = _eng()
    resp = make_response("")
    result = await eng.on_response(make_ctx(), resp)
    assert result is not None


async def test_unknown_profile_defaults_to_pci() -> None:
    eng = ProtectionEngine(profile="nonexistent")
    # Should fall back to pci profile (has credit_card)
    resp = make_response("Card: 4111111111111111")
    with pytest.raises(PIILeakError):
        await eng.on_response(make_ctx(), resp)


# ---------------------------------------------------------------------------
# Request passthrough
# ---------------------------------------------------------------------------


async def test_on_request_passthrough() -> None:
    from tests.conftest import make_request

    eng = _eng()
    ctx = make_ctx()
    req = make_request()
    result = await eng.on_request(ctx, req)
    assert result is ctx
