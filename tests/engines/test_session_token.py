"""Robustness tests for the stateless HMAC session signer (T7).

Five dimensions:
  - sunny day:     mint → verify round-trips
  - realistic:     cross-instance survival (the production incident)
  - corner cases:  malformed / empty / multi-dot tokens
  - flakiness:     nonce uniqueness, no time-dependence
  - adversarial:   forged / tampered / truncated / cross-transport / cross-secret
"""

from __future__ import annotations

import pytest

from mcp_armor.engines._session_token import (
    _MIN_SECRET_BYTES,
    SessionSigner,
)
from mcp_armor.exceptions import SessionError

_SECRET = b"x" * _MIN_SECRET_BYTES
_SECRET_B = b"y" * _MIN_SECRET_BYTES  # a *different* instance's (wrong) secret


def _signer(secret: bytes = _SECRET) -> SessionSigner:
    return SessionSigner(secret)


# --------------------------------------------------------------------------- #
# Sunny day
# --------------------------------------------------------------------------- #

def test_mint_then_verify_roundtrips() -> None:
    s = _signer()
    token = s.mint("http")
    s.verify(token, "http")  # must not raise


def test_token_shape_is_nonce_dot_sig() -> None:
    token = _signer().mint("http")
    assert token.count(".") == 1
    nonce, sig = token.split(".")
    assert nonce and sig
    assert "=" not in token  # urlsafe, unpadded — header-safe


# --------------------------------------------------------------------------- #
# Realistic — the production incident this fix exists for
# --------------------------------------------------------------------------- #

def test_token_verifies_on_a_DIFFERENT_signer_with_same_secret() -> None:
    """Instance A mints; instance B (fresh process, same secret) must accept it.

    This is the exact scenario the in-memory store failed: B had no record of
    A's session and raised a spurious T7-001 'unknown session'.
    """
    minted_on_instance_a = _signer(_SECRET).mint("http")
    instance_b = _signer(_SECRET)  # separate object == separate Cloud Run instance
    instance_b.verify(minted_on_instance_a, "http")  # must not raise


def test_token_rejected_when_other_instance_has_a_different_secret() -> None:
    """Proves the secret must be shared across instances (Secret Manager), not
    per-process — a per-process random key would reproduce the original bug."""
    minted_on_instance_a = _signer(_SECRET).mint("http")
    instance_b = _signer(_SECRET_B)
    with pytest.raises(SessionError, match="signature mismatch"):
        instance_b.verify(minted_on_instance_a, "http")


# --------------------------------------------------------------------------- #
# Corner cases — malformed tokens
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "bad",
    [
        "",                       # empty
        "no-dot-at-all",          # missing separator
        ".",                      # both parts empty
        "nonce.",                 # empty sig
        ".sig",                   # empty nonce
        "a.b.c",                  # too many parts
        "nonce.sig.",             # trailing dot → 3 parts
    ],
)
def test_malformed_token_rejected(bad: str) -> None:
    with pytest.raises(SessionError):
        _signer().verify(bad, "http")


# --------------------------------------------------------------------------- #
# Flakiness guards
# --------------------------------------------------------------------------- #

def test_mint_is_unique_per_call() -> None:
    s = _signer()
    tokens = {s.mint("http") for _ in range(1000)}
    assert len(tokens) == 1000  # nonce entropy — no collisions


def test_verify_is_deterministic_not_time_dependent() -> None:
    s = _signer()
    token = s.mint("http")
    for _ in range(100):
        s.verify(token, "http")  # no expiry / clock dependence → never flakes


# --------------------------------------------------------------------------- #
# Adversarial
# --------------------------------------------------------------------------- #

def test_forged_signature_rejected() -> None:
    s = _signer()
    nonce = s.mint("http").split(".")[0]
    with pytest.raises(SessionError, match="signature mismatch"):
        s.verify(f"{nonce}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "http")


def test_tampered_nonce_rejected() -> None:
    s = _signer()
    nonce, sig = s.mint("http").split(".")
    tampered = ("B" + nonce[1:]) if nonce[0] != "B" else ("C" + nonce[1:])
    with pytest.raises(SessionError, match="signature mismatch"):
        s.verify(f"{tampered}.{sig}", "http")


def test_truncated_signature_rejected() -> None:
    s = _signer()
    nonce, sig = s.mint("http").split(".")
    with pytest.raises(SessionError, match="signature mismatch"):
        s.verify(f"{nonce}.{sig[:-4]}", "http")


def test_cross_transport_replay_rejected() -> None:
    """T7-003: a token minted for one transport must not verify on another —
    transport is bound into the MAC."""
    s = _signer()
    http_token = s.mint("http")
    with pytest.raises(SessionError, match="signature mismatch"):
        s.verify(http_token, "stdio")


def test_signature_swap_between_two_tokens_rejected() -> None:
    s = _signer()
    n1, _ = s.mint("http").split(".")
    _, sig2 = s.mint("http").split(".")
    with pytest.raises(SessionError, match="signature mismatch"):
        s.verify(f"{n1}.{sig2}", "http")


# --------------------------------------------------------------------------- #
# Fail-closed construction
# --------------------------------------------------------------------------- #

def test_short_secret_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="too short"):
        SessionSigner(b"too-short")


def test_from_env_raises_when_secret_absent() -> None:
    with pytest.raises(RuntimeError, match="ARMOR_SESSION_SECRET is not set"):
        SessionSigner.from_env(env={})


def test_from_env_raises_when_secret_too_short() -> None:
    with pytest.raises(ValueError, match="too short"):
        SessionSigner.from_env(env={"ARMOR_SESSION_SECRET": "short"})


def test_from_env_builds_when_secret_present() -> None:
    s = SessionSigner.from_env(env={"ARMOR_SESSION_SECRET": "z" * _MIN_SECRET_BYTES})
    s.verify(s.mint("http"), "http")  # functional


def test_oversized_token_rejected_before_hmac() -> None:
    """Adversary EXPLOIT[2]: the session header is not size-capped upstream, so
    verify() must reject an absurdly long token BEFORE computing the HMAC over
    attacker-sized input."""
    s = _signer()
    nonce, sig = s.mint("http").split(".")
    bloated = f"{nonce}{'A' * 10_000}.{sig}"  # > _MAX_TOKEN_LEN
    with pytest.raises(SessionError, match="Malformed session token"):
        s.verify(bloated, "http")


def test_token_at_realistic_length_still_accepted() -> None:
    """Guard against the length cap being set too low and breaking real tokens."""
    s = _signer()
    s.verify(s.mint("http"), "http")  # ~70 chars, well under the cap
