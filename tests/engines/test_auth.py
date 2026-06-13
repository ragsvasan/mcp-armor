"""Tests for AuthEngine — T1: JWT verification, JTI replay, session binding, DPoP (RFC 9449)."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid

import pytest

joserfc = pytest.importorskip("joserfc", reason="joserfc not installed")

from joserfc import jwt as jose_jwt  # noqa: E402
from joserfc.jwk import ECKey, OctKey  # noqa: E402

from mcp_armor.engines.auth import AuthEngine, _JTICache, _jwk_thumbprint  # noqa: E402
from mcp_armor.exceptions import AuthenticationError  # noqa: E402
from tests.conftest import make_ctx, make_request  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _hmac_key():
    return OctKey.generate_key(256)


def _hmac_jwks(key) -> dict:
    return {"keys": [key.as_dict()]}


def _signed_jwt(claims: dict, key) -> str:
    return jose_jwt.encode({"alg": "HS256"}, claims, key)


def _now_claims(**extra) -> dict:
    return {
        "sub": "user-1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "jti": str(uuid.uuid4()),
        **extra,
    }


def _engine(key=None, require_dpop=False, **kwargs):
    """Build a test AuthEngine with a real HMAC key (fail-closed default)."""
    if key is None:
        key = _hmac_key()
    return AuthEngine(require_dpop=require_dpop, jwks=_hmac_jwks(key), **kwargs), key


def _ec_keypair():
    return ECKey.generate_key("P-256")


def _public_jwk(ec_key) -> dict:
    d = ec_key.as_dict()
    return {k: v for k, v in d.items() if k != "d"}


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _ath(access_token: str) -> str:
    return _b64url_encode(hashlib.sha256(access_token.encode()).digest())


def _dpop_proof(
    access_token: str,
    ec_key,
    *,
    htm: str = "POST",
    htu: str = "https://example.com/mcp",
    iat: int | None = None,
    jti: str | None = None,
    ath_override: str | None = None,
    include_ath: bool = True,
    typ: str = "dpop+jwt",
    embed_private: bool = False,
    cnf_jkt: str | None = None,
) -> str:
    claims: dict = {
        "htm": htm,
        "htu": htu,
        "iat": iat if iat is not None else int(time.time()),
        "jti": jti or str(uuid.uuid4()),
    }
    if include_ath:
        claims["ath"] = ath_override or _ath(access_token)
    pub_jwk = ec_key.as_dict() if embed_private else _public_jwk(ec_key)
    return jose_jwt.encode(
        {"alg": "ES256", "typ": typ, "jwk": pub_jwk},
        claims,
        ec_key,
    )


def _auth_req(
    token: str,
    scheme: str = "Bearer",
    dpop: str | None = None,
    session_id: str | None = None,
):
    headers: dict = {"authorization": f"{scheme} {token}"}
    if dpop:
        headers["dpop"] = dpop
    return make_request(
        method="tools/call",
        params={"name": "search", "arguments": {"q": "hello"}},
        headers=headers,
        session_id=session_id,
    )


# ---------------------------------------------------------------------------
# _JTICache — time-based eviction
# ---------------------------------------------------------------------------


def test_jti_cache_new_jti_accepted():
    cache = _JTICache(10)
    assert cache.check_and_add("abc", time.time() + 3600) is True


def test_jti_cache_replayed_jti_rejected():
    cache = _JTICache(10)
    exp = time.time() + 3600
    cache.check_and_add("abc", exp)
    assert cache.check_and_add("abc", exp) is False


def test_jti_cache_expired_entry_allows_readd():
    """An expired JTI is evicted and can be added again (new token, same JTI is unlikely but ok)."""
    cache = _JTICache(10)
    # Add with an expiry in the past
    cache.check_and_add("abc", time.time() - 1)
    # After expiry, the same JTI can be re-added (expired token is gone)
    assert cache.check_and_add("abc", time.time() + 3600) is True


def test_regression_jti_cache_full_raises_not_evicts():
    """When cache is full of unexpired entries, new additions must raise, not silently evict."""
    cache = _JTICache(3)
    exp = time.time() + 3600
    cache.check_and_add("a", exp)
    cache.check_and_add("b", exp)
    cache.check_and_add("c", exp)
    # All unexpired — adding a 4th must raise, not evict "a"
    with pytest.raises(AuthenticationError, match="cache full"):
        cache.check_and_add("d", exp)
    # "a" must still be in the cache (not evicted)
    assert cache.check_and_add("a", exp) is False


# ---------------------------------------------------------------------------
# FIX[1] regression: jwks=None must be refused (fail-closed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_auth_refuses_when_jwks_unconfigured():
    """jwks=None must raise AuthenticationError on any token, not silently accept."""
    engine = AuthEngine(require_dpop=False, jwks=None)
    ctx = make_ctx()
    # Build a minimal syntactically valid JWT with no signature
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {"sub": "x", "exp": int(time.time()) + 3600, "iat": int(time.time())}
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    token = f"{header}.{payload}."
    req = _auth_req(token)
    with pytest.raises(AuthenticationError, match="No JWKS configured"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_regression_startup_raises_when_jwks_absent():
    engine = AuthEngine(require_dpop=False, jwks=None)
    with pytest.raises(ValueError, match="jwks="):
        await engine.on_startup()


# ---------------------------------------------------------------------------
# T1-001: Missing / malformed Authorization header
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_missing_auth_header_raises():
    engine, _ = _engine()
    ctx = make_ctx()
    req = make_request(method="tools/call", params={}, headers={})
    with pytest.raises(AuthenticationError, match="Authorization"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_regression_empty_token_raises():
    engine, _ = _engine()
    ctx = make_ctx()
    req = _auth_req("", scheme="Bearer")
    with pytest.raises(AuthenticationError):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_unknown_scheme_raises():
    engine, _ = _engine()
    ctx = make_ctx()
    req = make_request(headers={"authorization": "Basic dXNlcjpwYXNz"})
    with pytest.raises(AuthenticationError, match="scheme"):
        await engine.on_request(ctx, req)


# ---------------------------------------------------------------------------
# JWT verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valid_signed_jwt_passes():
    engine, key = _engine()
    ctx = make_ctx()
    token = _signed_jwt(_now_claims(), key)
    req = _auth_req(token)
    new_ctx = await engine.on_request(ctx, req)
    assert new_ctx.user_id == "user-1"


@pytest.mark.asyncio
async def test_regression_invalid_signature_raises():
    engine, _ = _engine(key=_hmac_key())  # engine uses key1
    wrong_key = _hmac_key()  # token signed with key2
    ctx = make_ctx()
    token = _signed_jwt(_now_claims(), wrong_key)
    req = _auth_req(token)
    with pytest.raises(AuthenticationError, match="verification failed"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_regression_expired_jwt_raises():
    engine, key = _engine()
    ctx = make_ctx()
    token = _signed_jwt({**_now_claims(), "exp": int(time.time()) - 1}, key)
    req = _auth_req(token)
    with pytest.raises(AuthenticationError, match="expired"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_nbf_in_future_raises():
    engine, key = _engine()
    ctx = make_ctx()
    token = _signed_jwt({**_now_claims(), "nbf": int(time.time()) + 3600}, key)
    req = _auth_req(token)
    with pytest.raises(AuthenticationError, match="not yet valid"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_missing_exp_raises():
    engine, key = _engine()
    ctx = make_ctx()
    claims = _now_claims()
    del claims["exp"]
    token = _signed_jwt(claims, key)
    req = _auth_req(token)
    with pytest.raises(AuthenticationError, match="exp"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_regression_token_too_old_raises():
    engine, key = _engine(token_expiry_max_secs=10)
    ctx = make_ctx()
    token = _signed_jwt(
        {
            **_now_claims(),
            "iat": int(time.time()) - 100,
            "exp": int(time.time()) + 3600,
        },
        key,
    )
    req = _auth_req(token)
    with pytest.raises(AuthenticationError, match="issued too long ago"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_regression_issuer_mismatch_raises():
    engine, key = _engine(issuer="https://expected.example.com")
    ctx = make_ctx()
    token = _signed_jwt({**_now_claims(), "iss": "https://wrong.example.com"}, key)
    req = _auth_req(token)
    with pytest.raises(AuthenticationError, match="issuer"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_regression_audience_mismatch_raises():
    engine, key = _engine(audience="mcp-server")
    ctx = make_ctx()
    token = _signed_jwt({**_now_claims(), "aud": "other-service"}, key)
    req = _auth_req(token)
    with pytest.raises(AuthenticationError, match="audience"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_audience_list_containing_expected_passes():
    engine, key = _engine(audience="mcp-server")
    ctx = make_ctx()
    token = _signed_jwt({**_now_claims(), "aud": ["mcp-server", "other"]}, key)
    req = _auth_req(token)
    new_ctx = await engine.on_request(ctx, req)
    assert new_ctx.user_id == "user-1"


# ---------------------------------------------------------------------------
# FIX[2] regression: iss/aud enforced even without keyset (unconditional)
# The engine now always verifies sig (no unsigned path), so iss/aud always run.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_iss_aud_always_enforced():
    """iss/aud checks must run regardless of whether sig verification path was taken."""
    engine, key = _engine(issuer="https://expected.example.com")
    ctx = make_ctx()
    # Token signed correctly but wrong issuer
    token = _signed_jwt({**_now_claims(), "iss": "https://evil.example.com"}, key)
    req = _auth_req(token)
    with pytest.raises(AuthenticationError, match="issuer"):
        await engine.on_request(ctx, req)


# ---------------------------------------------------------------------------
# FIX[13] regression: malformed exp/iat claims must be 401, not 500
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_malformed_exp_claim_returns_auth_error():
    """exp='never' must raise AuthenticationError, not TypeError."""
    engine, key = _engine()
    ctx = make_ctx()
    token = _signed_jwt({**_now_claims(), "exp": "never"}, key)
    req = _auth_req(token)
    with pytest.raises(AuthenticationError):
        await engine.on_request(ctx, req)


# ---------------------------------------------------------------------------
# T1-002: JTI replay
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_jti_replay_raises():
    engine, key = _engine()
    ctx = make_ctx()
    jti = str(uuid.uuid4())
    token1 = _signed_jwt({**_now_claims(), "jti": jti}, key)
    await engine.on_request(ctx, _auth_req(token1))

    token2 = _signed_jwt({**_now_claims(), "jti": jti}, key)
    with pytest.raises(AuthenticationError, match="JTI replayed"):
        await engine.on_request(ctx, _auth_req(token2))


# ---------------------------------------------------------------------------
# T1-003: Session binding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_cross_session_token_reuse_rejected():
    """Token with sid=session_A must be rejected if presented in session_B."""
    engine, key = _engine()
    session_a = str(uuid.uuid4())
    session_b = str(uuid.uuid4())
    token = _signed_jwt({**_now_claims(), "sid": session_a}, key)
    ctx_b = make_ctx(session_id=session_b)
    req = _auth_req(token, session_id=session_b)
    with pytest.raises(AuthenticationError, match="session binding"):
        await engine.on_request(ctx_b, req)


@pytest.mark.asyncio
async def test_token_with_matching_sid_passes():
    engine, key = _engine()
    sid = str(uuid.uuid4())
    token = _signed_jwt({**_now_claims(), "sid": sid}, key)
    ctx = make_ctx(session_id=sid)
    req = _auth_req(token, session_id=sid)
    new_ctx = await engine.on_request(ctx, req)
    assert new_ctx.user_id == "user-1"


# ---------------------------------------------------------------------------
# T1-004: DPoP validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_dpop_required_but_absent_raises():
    engine, key = _engine(require_dpop=True, endpoint_uri="https://example.com/mcp")
    ctx = make_ctx()
    token = _signed_jwt(_now_claims(), key)
    req = _auth_req(token, scheme="DPoP")  # no dpop header
    with pytest.raises(AuthenticationError, match="DPoP.*absent"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_regression_dpop_scheme_required_but_bearer_used_raises():
    engine, key = _engine(require_dpop=True, endpoint_uri="https://example.com/mcp")
    ctx = make_ctx()
    token = _signed_jwt(_now_claims(), key)
    ec_key = _ec_keypair()
    proof = _dpop_proof(token, ec_key)
    req = _auth_req(token, scheme="Bearer", dpop=proof)
    with pytest.raises(AuthenticationError, match="scheme"):
        await engine.on_request(ctx, req)


@pytest.mark.asyncio
async def test_dpop_valid_proof_passes():
    key = _hmac_key()
    ec_key = _ec_keypair()
    engine = AuthEngine(
        require_dpop=True,
        jwks=_hmac_jwks(key),
        endpoint_uri="https://example.com/mcp",
        require_cnf_binding=False,  # isolate proof validity from cnf-binding gate
    )
    ctx = make_ctx()
    token = _signed_jwt(_now_claims(), key)
    proof = _dpop_proof(token, ec_key, htu="https://example.com/mcp")
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    new_ctx = await engine.on_request(ctx, req)
    assert new_ctx.user_id == "user-1"


@pytest.mark.asyncio
async def test_regression_dpop_wrong_typ_raises():
    engine, key = _engine(require_cnf_binding=False)
    ec_key = _ec_keypair()
    token = _signed_jwt(_now_claims(), key)
    proof = _dpop_proof(token, ec_key, typ="JWT")
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    with pytest.raises(AuthenticationError, match="typ=dpop\\+jwt"):
        await engine.on_request(ctx=make_ctx(), req=req)


@pytest.mark.asyncio
async def test_regression_dpop_stale_iat_raises():
    engine, key = _engine(dpop_max_age_secs=30, require_cnf_binding=False)
    ec_key = _ec_keypair()
    token = _signed_jwt(_now_claims(), key)
    proof = _dpop_proof(token, ec_key, iat=int(time.time()) - 120)
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    with pytest.raises(AuthenticationError, match="iat too old"):
        await engine.on_request(ctx=make_ctx(), req=req)


@pytest.mark.asyncio
async def test_regression_dpop_iat_future_window_capped_at_skew():
    """Proof with iat > now + dpop_future_skew_secs must be rejected."""
    engine, key = _engine(
        dpop_max_age_secs=30, dpop_future_skew_secs=5, require_cnf_binding=False
    )
    ec_key = _ec_keypair()
    token = _signed_jwt(_now_claims(), key)
    proof = _dpop_proof(token, ec_key, iat=int(time.time()) + 25)
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    with pytest.raises(AuthenticationError, match="future"):
        await engine.on_request(ctx=make_ctx(), req=req)


@pytest.mark.asyncio
async def test_regression_dpop_jti_replay_raises():
    engine, key = _engine(require_cnf_binding=False)
    ec_key = _ec_keypair()
    dpop_jti = str(uuid.uuid4())

    token1 = _signed_jwt(_now_claims(), key)
    proof1 = _dpop_proof(token1, ec_key, jti=dpop_jti)
    await engine.on_request(make_ctx(), _auth_req(token1, scheme="DPoP", dpop=proof1))

    token2 = _signed_jwt(_now_claims(), key)
    proof2 = _dpop_proof(token2, ec_key, jti=dpop_jti)
    with pytest.raises(AuthenticationError, match="DPoP JTI replayed"):
        await engine.on_request(make_ctx(), _auth_req(token2, scheme="DPoP", dpop=proof2))


@pytest.mark.asyncio
async def test_regression_dpop_ath_mismatch_raises():
    engine, key = _engine(require_cnf_binding=False)
    ec_key = _ec_keypair()
    token = _signed_jwt(_now_claims(), key)
    wrong_ath = _b64url_encode(hashlib.sha256(b"wrong").digest())
    proof = _dpop_proof(token, ec_key, ath_override=wrong_ath)
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    with pytest.raises(AuthenticationError, match="ath binding"):
        await engine.on_request(make_ctx(), req)


@pytest.mark.asyncio
async def test_regression_dpop_private_key_in_header_raises():
    engine, key = _engine(require_cnf_binding=False)
    ec_key = _ec_keypair()
    token = _signed_jwt(_now_claims(), key)
    proof = _dpop_proof(token, ec_key, embed_private=True)
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    with pytest.raises(AuthenticationError, match="private key"):
        await engine.on_request(make_ctx(), req)


@pytest.mark.asyncio
async def test_regression_dpop_htm_mismatch_raises():
    """DPoP htm must match the fixed transport method (POST); GET proof is rejected."""
    engine, key = _engine(require_cnf_binding=False)
    ec_key = _ec_keypair()
    token = _signed_jwt(_now_claims(), key)
    proof = _dpop_proof(token, ec_key, htm="GET")
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    with pytest.raises(AuthenticationError, match="htm mismatch"):
        await engine.on_request(make_ctx(), req)


@pytest.mark.asyncio
async def test_regression_dpop_htu_mismatch_raises():
    key = _hmac_key()
    engine = AuthEngine(
        require_dpop=True,
        jwks=_hmac_jwks(key),
        endpoint_uri="https://example.com/mcp",
        require_cnf_binding=False,  # isolate htu binding from cnf-binding gate
    )
    ec_key = _ec_keypair()
    token = _signed_jwt(_now_claims(), key)
    proof = _dpop_proof(token, ec_key, htu="https://attacker.example.com/mcp")
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    with pytest.raises(AuthenticationError, match="htu mismatch"):
        await engine.on_request(make_ctx(), req)


# ---------------------------------------------------------------------------
# FIX[3] regression: cnf.jkt thumbprint binding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_dpop_jkt_thumbprint_must_match_cnf():
    """Proof signed with key whose thumbprint differs from access-token cnf.jkt is rejected."""
    key = _hmac_key()
    engine = AuthEngine(require_dpop=False, jwks=_hmac_jwks(key))
    ec_key_a = _ec_keypair()
    ec_key_b = _ec_keypair()  # attacker's key — different from cnf key

    pub_a = _public_jwk(ec_key_a)
    jkt_a = _jwk_thumbprint(pub_a)

    # Token claims cnf.jkt = thumbprint(key_a)
    token = _signed_jwt({**_now_claims(), "cnf": {"jkt": jkt_a}}, key)
    # But proof is signed with key_b (attacker's key)
    proof = _dpop_proof(token, ec_key_b)
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    with pytest.raises(AuthenticationError, match="cnf.jkt"):
        await engine.on_request(make_ctx(), req)


@pytest.mark.asyncio
async def test_dpop_jkt_matching_thumbprint_passes():
    key = _hmac_key()
    engine = AuthEngine(require_dpop=False, jwks=_hmac_jwks(key))
    ec_key = _ec_keypair()
    pub = _public_jwk(ec_key)
    jkt = _jwk_thumbprint(pub)
    token = _signed_jwt({**_now_claims(), "cnf": {"jkt": jkt}}, key)
    proof = _dpop_proof(token, ec_key)
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    new_ctx = await engine.on_request(make_ctx(), req)
    assert new_ctx.user_id == "user-1"


# ---------------------------------------------------------------------------
# FIX[4] regression: cnf.jkt in token forces DPoP mandatory
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_cnf_jkt_token_requires_dpop_proof():
    """Token with cnf.jkt must require DPoP even when require_dpop=False."""
    key = _hmac_key()
    ec_key = _ec_keypair()
    pub = _public_jwk(ec_key)
    jkt = _jwk_thumbprint(pub)
    engine = AuthEngine(require_dpop=False, jwks=_hmac_jwks(key))
    token = _signed_jwt({**_now_claims(), "cnf": {"jkt": jkt}}, key)
    req = _auth_req(token, scheme="Bearer")  # no DPoP proof
    with pytest.raises(AuthenticationError, match="sender-constrained.*DPoP.*required"):
        await engine.on_request(make_ctx(), req)


# ---------------------------------------------------------------------------
# RFC 9449 §4.3 regression: when DPoP is in force the access token MUST be
# sender-constrained (carry cnf.jkt). A valid proof against an unbound token is
# never bound to it, so a stolen non-bound token could be replayed with any
# attacker-minted proof. Fail closed.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_dpop_without_cnf_jkt_rejected():
    """require_dpop=True + valid proof but token lacks cnf.jkt → rejected."""
    key = _hmac_key()
    ec_key = _ec_keypair()
    engine = AuthEngine(
        require_dpop=True,
        jwks=_hmac_jwks(key),
        endpoint_uri="https://example.com/mcp",
    )
    token = _signed_jwt(_now_claims(), key)  # no cnf claim
    proof = _dpop_proof(token, ec_key, htu="https://example.com/mcp")
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    with pytest.raises(AuthenticationError, match="cnf.jkt|4.3"):
        await engine.on_request(make_ctx(), req)


@pytest.mark.asyncio
async def test_regression_dpop_proof_without_cnf_jkt_rejected_even_if_not_required():
    """A presented DPoP proof against an unbound token is rejected even when
    require_dpop=False — the proof implies an (illusory) binding guarantee."""
    key = _hmac_key()
    ec_key = _ec_keypair()
    engine = AuthEngine(require_dpop=False, jwks=_hmac_jwks(key))
    token = _signed_jwt(_now_claims(), key)  # no cnf claim
    proof = _dpop_proof(token, ec_key)
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    with pytest.raises(AuthenticationError, match="cnf.jkt|4.3"):
        await engine.on_request(make_ctx(), req)


@pytest.mark.asyncio
async def test_dpop_without_cnf_jkt_accepted_when_binding_opt_out():
    """require_cnf_binding=False is the explicit accepted-risk opt-out."""
    key = _hmac_key()
    ec_key = _ec_keypair()
    engine = AuthEngine(
        require_dpop=True,
        jwks=_hmac_jwks(key),
        endpoint_uri="https://example.com/mcp",
        require_cnf_binding=False,
    )
    token = _signed_jwt(_now_claims(), key)  # no cnf claim
    proof = _dpop_proof(token, ec_key, htu="https://example.com/mcp")
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    new_ctx = await engine.on_request(make_ctx(), req)
    assert new_ctx.user_id == "user-1"


@pytest.mark.asyncio
async def test_regression_bearer_no_dpop_cnf_gate_not_triggered():
    """Plain Bearer flow (no DPoP in force) must be untouched by the cnf gate:
    require_cnf_binding=True default, require_dpop=False, no DPoP header, token
    without cnf.jkt → accepted."""
    engine, key = _engine(require_dpop=False)  # require_cnf_binding defaults True
    token = _signed_jwt(_now_claims(), key)  # no cnf claim
    req = _auth_req(token, scheme="Bearer")  # no DPoP header
    new_ctx = await engine.on_request(make_ctx(), req)
    assert new_ctx.user_id == "user-1"


# ---------------------------------------------------------------------------
# FIX[5] regression: htm must use transport method, not client-supplied header
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_dpop_htm_not_taken_from_client_header():
    """x-mcp-http-method header from client must NOT influence htm validation."""
    engine, key = _engine(require_cnf_binding=False)
    ec_key = _ec_keypair()
    token = _signed_jwt(_now_claims(), key)
    # Proof says GET — attacker also sets x-mcp-http-method: GET hoping to match
    proof = _dpop_proof(token, ec_key, htm="GET")
    headers = {
        "authorization": f"DPoP {token}",
        "dpop": proof,
        "x-mcp-http-method": "GET",  # client lies about the method
    }
    req = make_request(method="tools/call", params={}, headers=headers)
    # Engine must use "POST" (real transport method), not the header — proof rejected
    with pytest.raises(AuthenticationError, match="htm mismatch"):
        await engine.on_request(make_ctx(), req)


# ---------------------------------------------------------------------------
# FIX[11] regression: Bearer scheme with DPoP proof must be rejected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_bearer_scheme_with_dpop_proof_rejected():
    """Authorization: Bearer + DPoP header together must be rejected (RFC 9449 §7.1)."""
    engine, key = _engine()
    ec_key = _ec_keypair()
    token = _signed_jwt(_now_claims(), key)
    proof = _dpop_proof(token, ec_key)
    req = _auth_req(token, scheme="Bearer", dpop=proof)
    with pytest.raises(AuthenticationError, match="Bearer.*DPoP|DPoP.*Bearer"):
        await engine.on_request(make_ctx(), req)


# ---------------------------------------------------------------------------
# FIX[14] regression: weak RSA DPoP key must be rejected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_dpop_weak_rsa_key_rejected():
    """DPoP proof signed with an RSA key below 2048 bits must be rejected."""
    from joserfc.jwk import RSAKey

    engine, key = _engine(require_cnf_binding=False)
    token = _signed_jwt(_now_claims(), key)

    rsa_key = RSAKey.generate_key(1024, private=True)  # deliberately weak
    pub_jwk = {k: v for k, v in rsa_key.as_dict().items() if k != "d"}

    # Build proof manually with RS256 and the weak RSA key
    claims_body = {
        "htm": "POST",
        "htu": "https://example.com/mcp",
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
        "ath": _ath(token),
    }
    proof = jose_jwt.encode(
        {"alg": "RS256", "typ": "dpop+jwt", "jwk": pub_jwk},
        claims_body,
        rsa_key,
    )
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    with pytest.raises(AuthenticationError, match="2048|RSA|bits"):
        await engine.on_request(make_ctx(), req)


# ---------------------------------------------------------------------------
# C2 regression (AUDIT_2026-06-12): malformed RSA modulus must be REJECTED, not
# silently skipped. _check_rsa_key_size previously did `except Exception: return`,
# letting an attacker bypass the NIST key-size floor with an undecodable `n`.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_c2_dpop_malformed_rsa_modulus_rejected():
    """DPoP proof embedding an RSA JWK whose `n` cannot be base64-decoded must
    be rejected (fail closed), not skipped."""
    engine, key = _engine(require_cnf_binding=False)
    token = _signed_jwt(_now_claims(), key)

    # Sign the proof with a real key, but advertise a malformed modulus in the
    # embedded JWK header — _check_rsa_key_size runs on the header before the
    # signature is verified, so the malformed `n` is what gets rejected.
    from joserfc.jwk import RSAKey

    signing_key = RSAKey.generate_key(2048, private=True)
    bad_jwk = {"kty": "RSA", "n": "A", "e": "AQAB"}  # "A" -> invalid b64 length
    claims_body = {
        "htm": "POST",
        "htu": "https://example.com/mcp",
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
        "ath": _ath(token),
    }
    proof = jose_jwt.encode(
        {"alg": "RS256", "typ": "dpop+jwt", "jwk": bad_jwk},
        claims_body,
        signing_key,
    )
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    with pytest.raises(AuthenticationError, match="malformed|modulus|key size"):
        await engine.on_request(make_ctx(), req)


# ---------------------------------------------------------------------------
# FIX[15] regression: error messages must not leak raw token content
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_auth_error_does_not_leak_token():
    """JWT verification errors must not include the raw token string."""
    engine, _ = _engine()
    secret_token = "eyJhbGciOiJIUzI1NiJ9.sensitive_data_here.bad_sig"
    req = make_request(
        method="tools/call",
        params={},
        headers={"authorization": f"Bearer {secret_token}"},
    )
    with pytest.raises(AuthenticationError) as exc_info:
        await engine.on_request(make_ctx(), req)
    assert secret_token not in str(exc_info.value), (
        "Error message must not contain the raw token (token leakage)"
    )


# ---------------------------------------------------------------------------
# FIX[16] regression: conflicting tenant claims must be rejected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_conflicting_tenant_claims_rejected():
    """Token with tenant_id != tid must be rejected (privilege-escalation via claim confusion)."""
    engine, key = _engine()
    claims = {**_now_claims(), "tenant_id": "tenant-A", "tid": "tenant-B"}
    token = _signed_jwt(claims, key)
    req = _auth_req(token, scheme="Bearer")
    with pytest.raises(AuthenticationError, match="[Cc]onflicting tenant"):
        await engine.on_request(make_ctx(), req)


@pytest.mark.asyncio
async def test_matching_tenant_claims_passes():
    """Token where tenant_id == tid is not ambiguous and must pass."""
    engine, key = _engine()
    claims = {**_now_claims(), "tenant_id": "tenant-A", "tid": "tenant-A"}
    token = _signed_jwt(claims, key)
    req = _auth_req(token, scheme="Bearer")
    new_ctx = await engine.on_request(make_ctx(), req)
    assert new_ctx.tenant_id == "tenant-A"


# ---------------------------------------------------------------------------
# Startup validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_startup_raises_if_dpop_required_and_no_endpoint_uri():
    engine = AuthEngine(require_dpop=True, jwks=_hmac_jwks(_hmac_key()), endpoint_uri=None)
    with pytest.raises(ValueError, match="endpoint_uri"):
        await engine.on_startup()


@pytest.mark.asyncio
async def test_startup_ok_when_configured():
    engine = AuthEngine(
        require_dpop=True,
        jwks=_hmac_jwks(_hmac_key()),
        endpoint_uri="https://example.com/mcp",
    )
    await engine.on_startup()  # must not raise
