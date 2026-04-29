"""Tests for T11 SupplyChainEngine — allowlist, Levenshtein, NFKC homoglyph, Ed25519."""

from __future__ import annotations

import json
import pytest

from mcp_armor.engines.supply_chain import SupplyChainEngine
from mcp_armor.exceptions import SupplyChainError
from tests.conftest import make_ctx, make_request


def _engine(
    allowlist=None,
    require_sig=False,
    threshold=1,
    pub_key=None,
) -> SupplyChainEngine:
    return SupplyChainEngine(
        tool_allowlist=allowlist,
        require_registry_signature=require_sig,
        levenshtein_threshold=threshold,
        registry_public_key=pub_key,
    )


# ---------------------------------------------------------------------------
# T11-001: Allowlist enforcement
# ---------------------------------------------------------------------------

def test_allowlisted_tool_passes() -> None:
    eng = _engine(allowlist=["tool_a", "tool_b"])
    eng.validate_tools([{"name": "tool_a"}, {"name": "tool_b"}])


def test_unlisted_tool_denied() -> None:
    eng = _engine(allowlist=["tool_a"])
    with pytest.raises(SupplyChainError, match="not on the approved allowlist"):
        eng.validate_tools([{"name": "evil_tool"}])


def test_no_allowlist_allows_all() -> None:
    eng = _engine(allowlist=None)
    eng.validate_tools([{"name": "anything"}, {"name": "whatever"}])


def test_empty_allowlist_denies_all() -> None:
    """Empty list → normalised to None by load_config, but direct construction allows it."""
    # When allowlist=[] is passed directly (not via load_config), it becomes an empty set
    eng = SupplyChainEngine(tool_allowlist=[], require_registry_signature=False)
    # Empty allowlist set → any tool not in set raises
    with pytest.raises(SupplyChainError):
        eng.validate_tools([{"name": "any_tool"}])


# ---------------------------------------------------------------------------
# T11-002: Typosquatting (Levenshtein)
# ---------------------------------------------------------------------------

def test_typosquat_within_threshold_denied() -> None:
    eng = _engine(allowlist=["tools_list"], threshold=1)
    # "toolslist" = 1 deletion from "tools_list"
    with pytest.raises(SupplyChainError, match="Levenshtein"):
        eng.validate_tools([{"name": "toolslist"}])


def test_typosquat_above_threshold_raises_allowlist_not_levenshtein() -> None:
    """
    A tool differing by more than the Levenshtein threshold is not a typosquat hit,
    but it still fails the allowlist check (T11-001) — different error message.
    """
    eng = _engine(allowlist=["tool_a"], threshold=1)
    # "tXYl_a" is distance 2 — no typosquat error, but still not on allowlist
    with pytest.raises(SupplyChainError, match="not on the approved allowlist"):
        eng.validate_tools([{"name": "tXYl_a"}])


def test_exact_allowlist_match_with_threshold() -> None:
    eng = _engine(allowlist=["tools_list"], threshold=1)
    eng.validate_tools([{"name": "tools_list"}])


# ---------------------------------------------------------------------------
# T11-ADV-001: NFKC homoglyph attack
# ---------------------------------------------------------------------------

def test_nfkc_lookalike_allowlist_match_passes() -> None:
    """Fullwidth variant NFKC-normalizes to the allowlisted name — should pass."""
    eng = _engine(allowlist=["tool_a"])
    fullwidth = "ｔool_a"  # NFKC → "tool_a"
    eng.validate_tools([{"name": fullwidth}])


def test_nfkc_lookalike_not_on_allowlist_denied() -> None:
    """A Unicode lookalike that normalizes to a name NOT on the allowlist is still denied."""
    eng = _engine(allowlist=["tool_a"])
    # ｂool_a → NFKC → "bool_a" — not on allowlist; also 1 edit from "tool_a" → typosquat
    with pytest.raises(SupplyChainError):
        eng.validate_tools([{"name": "ｂool_a"}])


def test_nfkc_typosquat_within_threshold_denied() -> None:
    """Unicode lookalike whose NFKC form is within Levenshtein distance of an allowlisted name."""
    eng = _engine(allowlist=["tools_list"], threshold=1)
    # ｔoolslist → NFKC → "toolslist" — distance 1 from "tools_list"
    with pytest.raises(SupplyChainError):
        eng.validate_tools([{"name": "ｔoolslist"}])


# ---------------------------------------------------------------------------
# T11-003: Ed25519 registry signature
# ---------------------------------------------------------------------------

def test_signature_required_but_missing_denied() -> None:
    eng = _engine(allowlist=["my_tool"], require_sig=True)
    # We're not setting a pub_key here; on_startup would fail, but validate_tools
    # checks the sig field presence first
    with pytest.raises((SupplyChainError, ValueError)):
        eng.validate_tools([{"name": "my_tool"}])


def test_signature_not_required_skipped() -> None:
    eng = _engine(allowlist=["my_tool"], require_sig=False)
    eng.validate_tools([{"name": "my_tool"}])  # no _sig field — OK


def test_ed25519_signature_roundtrip() -> None:
    """Generate a real Ed25519 key pair, sign a tool definition, verify it passes."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, NoEncryption, PrivateFormat
    )
    import binascii

    # Generate key pair
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

    # Sign a tool definition
    tool = {"name": "my_tool", "description": "A tool"}
    canonical = json.dumps(tool, sort_keys=True, separators=(",", ":")).encode()
    sig = priv.sign(canonical)
    sig_hex = binascii.hexlify(sig).decode()

    eng = SupplyChainEngine(
        tool_allowlist=["my_tool"],
        require_registry_signature=True,
        registry_public_key=pub_pem,
    )
    tool_with_sig = {**tool, "_sig": sig_hex}
    eng.validate_tools([tool_with_sig])  # must not raise


def test_ed25519_wrong_signature_denied() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import binascii

    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()

    tool = {"name": "my_tool"}
    bad_sig = binascii.hexlify(b"\x00" * 64).decode()

    eng = SupplyChainEngine(
        tool_allowlist=["my_tool"],
        require_registry_signature=True,
        registry_public_key=pub_pem,
    )
    with pytest.raises(SupplyChainError, match="signature invalid"):
        eng.validate_tools([{"name": "my_tool", "_sig": bad_sig}])


# ---------------------------------------------------------------------------
# Lifecycle hooks (pass-throughs)
# ---------------------------------------------------------------------------

async def test_on_request_passthrough() -> None:
    eng = _engine()
    ctx = make_ctx()
    req = make_request()
    result = await eng.on_request(ctx, req)
    assert result is ctx


async def test_on_startup_no_sig_passes() -> None:
    eng = _engine(require_sig=False)
    await eng.on_startup()


async def test_on_startup_sig_required_without_key_raises() -> None:
    """FIX-3: on_startup must raise SupplyChainError (not ValueError) for consistency."""
    eng = _engine(require_sig=True, pub_key=None)
    with pytest.raises(SupplyChainError, match="registry_public_key"):
        await eng.on_startup()


# ---------------------------------------------------------------------------
# Panel regression tests
# ---------------------------------------------------------------------------

def test_regression_missing_name_key_raises() -> None:
    """FIX-2: entry without 'name' key must raise SupplyChainError, not TypeError."""
    eng = _engine(allowlist=["tool_a"])
    with pytest.raises(SupplyChainError):
        eng.validate_tools([{"description": "no name here"}])


def test_regression_non_string_name_raises() -> None:
    """FIX-2: non-string 'name' value must raise SupplyChainError, not TypeError."""
    eng = _engine(allowlist=["tool_a"])
    with pytest.raises(SupplyChainError):
        eng.validate_tools([{"name": None}])


async def test_regression_on_startup_raises_supply_chain_error() -> None:
    """FIX-3: startup misconfiguration must raise SupplyChainError so armor boundary catches it."""
    eng = _engine(require_sig=True, pub_key=None)
    with pytest.raises(SupplyChainError):
        await eng.on_startup()


def test_regression_bad_hex_sig_raises_supply_chain_error() -> None:
    """FIX-4: malformed hex signature must raise SupplyChainError, not unhandled binascii.Error."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()
    eng = SupplyChainEngine(
        tool_allowlist=["my_tool"],
        require_registry_signature=True,
        registry_public_key=pub_pem,
    )
    with pytest.raises(SupplyChainError):
        eng.validate_tools([{"name": "my_tool", "_sig": "not-valid-hex!"}])
