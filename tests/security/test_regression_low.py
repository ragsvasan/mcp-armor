"""Regression tests for the LOW-severity opus/fable audit fixes (2026-07-17).

One test per concrete fix landed on security/audit-2026-07-remediation,
scoped to boundary.py, trust.py, integrity.py, resources.py, and
supply_chain.py:

- boundary.py + trust.py: the response-injection scan no longer truncates to
  _MAX_SCAN_LEN (8192) before matching. When re2 is loaded it scans the full
  text with no cap (re2 is linear-time, so capping bought nothing); when re2
  is unavailable it slides overlapping windows across the full text instead
  of only ever looking at the first window. Closes the "payload past offset
  8192 evades detection" gap (same root cause as the response scan/forward
  asymmetry: scan what you forward).
- integrity.py: T6 manifest drift is now always logged and attached to
  ctx.findings, even when fail_on_drift=False — previously completely silent.
- resources.py: the T10 call/wall-clock budget now persists in a ledger keyed
  by session_id (the signed session token) beyond idle-eviction, so a slow
  attacker pacing calls past heartbeat_interval_secs can't reset it.
- supply_chain.py: the Ed25519-signed canonical body now excludes only the
  `_sig` field, not every `_`-prefixed key, so future `_`-fields are part of
  the authenticated body instead of an unsigned side channel.
"""

from __future__ import annotations

import json
import logging
from types import MappingProxyType

import pytest

from mcp_armor.engines.boundary import _MAX_SCAN_LEN, BoundaryEngine
from mcp_armor.engines.integrity import IntegrityEngine
from mcp_armor.engines.resources import ResourceEngine
from mcp_armor.engines.supply_chain import SupplyChainEngine
from mcp_armor.engines.trust import TrustEngine
from mcp_armor.exceptions import (
    InjectionDetectedError,
    ResourceExceededError,
    SupplyChainError,
    TrustBoundaryViolation,
)
from mcp_armor.types import MCPResponse
from tests.conftest import make_ctx, make_request, make_response

# ---------------------------------------------------------------------------
# boundary.py + trust.py — response injection scan no longer capped at 8192
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_windowed_scan_catches_payload_beyond_max_scan_len() -> None:
    """
    When re2 is unavailable, the response-injection scan must fall back to
    overlapping windows spanning the FULL body — not a single 8192-char
    truncation — so a payload placed past the old fixed offset is still
    caught. `_using_re2` is forced False so this exercises the fallback path
    deterministically regardless of whether re2 happens to be installed.

    Under the pre-fix code this raises nothing (the injection text sits past
    text[:_MAX_SCAN_LEN], which is all the old code ever looked at).
    """
    eng = BoundaryEngine()
    eng._using_re2 = False  # force the stdlib-re windowed fallback

    padding = "x" * (_MAX_SCAN_LEN + 500)
    resp = make_response(padding + "jailbreak mode enabled")
    with pytest.raises(InjectionDetectedError):
        await eng.on_response(make_ctx(), resp)


@pytest.mark.asyncio
async def test_regression_re2_scan_has_no_length_cap() -> None:
    """
    When re2 IS loaded, the response-injection scan must not truncate at
    _MAX_SCAN_LEN at all — re2 is linear-time regardless of input size, so
    the old cap only created a blind spot with no ReDoS benefit.
    """
    eng = BoundaryEngine()
    if not eng._using_re2:
        pytest.skip("re2 not installed in this environment")

    padding = "y" * (_MAX_SCAN_LEN * 3)
    resp = make_response(padding + "jailbreak mode enabled")
    with pytest.raises(InjectionDetectedError):
        await eng.on_response(make_ctx(), resp)


@pytest.mark.asyncio
async def test_regression_trust_engine_response_scan_beyond_max_scan_len() -> None:
    """
    TrustEngine.on_response delegates to BoundaryEngine._scan for the T9
    response path (trust.py has no truncation logic of its own) — confirm
    the shared fix closes the same offset-8192 detection gap there too.
    """
    engine = TrustEngine(strip_injection_patterns=True)
    padding = "z" * (_MAX_SCAN_LEN + 1000)
    resp = make_response(padding + "jailbreak mode enabled")
    with pytest.raises(TrustBoundaryViolation):
        await engine.on_response(make_ctx(), resp)


# ---------------------------------------------------------------------------
# integrity.py — T6 drift is always observable, even when not failing closed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_drift_finding_and_log_emitted_when_not_failing_closed(caplog) -> None:
    """
    With fail_on_drift=False, mid-session manifest drift (T6-001) must no
    longer be completely silent: a Finding is attached to ctx.findings and a
    warning is logged, through the same on_response entry point the guard
    pipeline calls after every tools/list re-fetch.
    """
    eng = IntegrityEngine(fail_on_drift=False)
    ctx = make_ctx()
    resp_v1 = MCPResponse(
        result=MappingProxyType({"tools": [{"name": "tool_a"}]}), error=None, raw_body=""
    )
    ctx = await eng.on_response(ctx, resp_v1)
    assert ctx.findings == ()

    resp_v2 = MCPResponse(
        result=MappingProxyType({"tools": [{"name": "tool_a"}, {"name": "evil_tool"}]}),
        error=None,
        raw_body="",
    )
    with caplog.at_level(logging.WARNING):
        ctx = await eng.on_response(ctx, resp_v2)

    assert any(f.code == "T6-001" for f in ctx.findings), (
        f"expected a T6-001 Finding attached to ctx, got: {ctx.findings}"
    )
    assert "rug-pull" in caplog.text, "expected a warning logged for the silent-drift case"


# ---------------------------------------------------------------------------
# resources.py — T10 budget persists across idle-eviction (denial-of-wallet)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_budget_persists_across_idle_eviction_and_context_rebuild() -> None:
    """
    The T10-001/002 call/wall-clock budget must survive the reaper evicting
    an idle session and the adapter rebuilding a fresh zero-budget
    CoSAIContext for the SAME signed session token — otherwise an attacker
    pacing calls just over heartbeat_interval_secs gets an unlimited
    long-horizon budget (denial-of-wallet).
    """
    eng = ResourceEngine(max_calls_per_session=3, heartbeat_interval_secs=30.0)
    session_id = "sess-token-abc"
    req = make_request(method="tools/call", params={"name": "t", "arguments": {}})

    ctx = make_ctx(session_id=session_id)
    ctx = await eng.on_session_start(ctx)
    ctx = await eng.on_request(ctx, req)
    ctx = await eng.on_request(ctx, req)
    assert ctx.budget.calls_used == 2

    # Simulate reaper eviction: idle-eviction (_reap_zombie_sessions) only
    # ever clears _session_last_seen — never the budget ledger.
    eng._session_last_seen.pop(session_id, None)

    # Simulate the adapter rebuilding a brand-new zero-budget context for the
    # same signed session token — exactly the vulnerable path being fixed.
    rebuilt_ctx = make_ctx(session_id=session_id)
    assert rebuilt_ctx.budget.calls_used == 0

    result = await eng.on_request(rebuilt_ctx, req)
    # Budget must resume from 2, not restart from 0.
    assert result.budget.calls_used == 3

    # The persisted budget (limit 3) is now correctly exhausted.
    with pytest.raises(ResourceExceededError, match="budget exhausted"):
        await eng.on_request(result, req)

    await eng.close()


# ---------------------------------------------------------------------------
# supply_chain.py — Ed25519 signature covers all fields except _sig itself
# ---------------------------------------------------------------------------


def test_regression_supply_chain_signature_covers_non_sig_underscore_fields() -> None:
    """
    Only `_sig` is excluded from the signed canonical body now — any OTHER
    `_`-prefixed field is part of what gets signed, so tampering with it
    after signing must be caught. Previously EVERY `_`-prefixed key was
    excluded, so a `_meta`-style field would have been unsigned side-channel
    data an attacker could freely rewrite without invalidating the signature.
    """
    import binascii

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    priv = Ed25519PrivateKey.generate()
    pub_pem = (
        priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    )

    tool = {"name": "my_tool", "_meta": "trusted-origin"}
    canonical = json.dumps(tool, sort_keys=True, separators=(",", ":")).encode()
    sig_hex = binascii.hexlify(priv.sign(canonical)).decode()

    eng = SupplyChainEngine(
        tool_allowlist=["my_tool"],
        require_registry_signature=True,
        registry_public_key=pub_pem,
    )
    tool_with_sig = {**tool, "_sig": sig_hex}
    eng.validate_tools([tool_with_sig])  # must not raise — signed body matches

    # Tamper with the non-_sig underscore field after signing.
    tampered = {**tool_with_sig, "_meta": "attacker-rewritten"}
    with pytest.raises(SupplyChainError, match="signature invalid"):
        eng.validate_tools([tampered])
