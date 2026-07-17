"""
Security regression tests — DPoP + access-token hardening (AUDIT 2026-07-17).

Covers three remediations, all in mcp_armor/engines/auth.py:

- M4 (cross-endpoint DPoP replay): _verify_dpop fails closed when endpoint_uri
  is unset, so a voluntarily-presented proof can never skip the htu binding.
- M5 (per-process jti cache): the DPoP jti replay store is pluggable — an
  injected shared store is consulted instead of the in-memory _JTICache.
- joserfc/HS* hardening: HS256/384/512 are included in the access-token
  algorithm allowlist only when the JWKS is exclusively `oct` keys; otherwise
  HS* is dropped (prevents RS/HS confusion + the joserfc empty-key surface).
"""

from __future__ import annotations

import base64
import hashlib
import time
import uuid

import pytest

joserfc = pytest.importorskip("joserfc", reason="joserfc not installed")

from joserfc import jwt as jose_jwt  # noqa: E402
from joserfc.jwk import ECKey, OctKey  # noqa: E402

from mcp_armor.engines.auth import AuthEngine  # noqa: E402
from mcp_armor.exceptions import AuthenticationError  # noqa: E402
from tests.conftest import make_ctx, make_request  # noqa: E402

_ENDPOINT = "https://example.com/mcp"


# ---------------------------------------------------------------------------
# Helpers (mirror tests/engines/test_auth.py so this file is self-contained)
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
    htu: str = _ENDPOINT,
    iat: int | None = None,
    jti: str | None = None,
) -> str:
    claims: dict = {
        "htm": htm,
        "htu": htu,
        "iat": iat if iat is not None else int(time.time()),
        "jti": jti or str(uuid.uuid4()),
        "ath": _ath(access_token),
    }
    return jose_jwt.encode(
        {"alg": "ES256", "typ": "dpop+jwt", "jwk": _public_jwk(ec_key)},
        claims,
        ec_key,
    )


def _auth_req(token: str, scheme: str = "DPoP", dpop: str | None = None):
    headers: dict = {"authorization": f"{scheme} {token}"}
    if dpop:
        headers["dpop"] = dpop
    return make_request(
        method="tools/call",
        params={"name": "search", "arguments": {"q": "hello"}},
        headers=headers,
    )


class _FakeSharedJTIStore:
    """A stand-in for a shared (e.g. Redis-backed) jti replay store.

    Records every check_and_add call so the test can assert the engine
    consulted the injected store rather than its internal in-memory cache.
    Implements the JTIReplayStore Protocol structurally.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, float]] = []
        self._seen: set[str] = set()

    def check_and_add(self, jti: str, exp: float) -> bool:
        self.calls.append((jti, exp))
        if jti in self._seen:
            return False
        self._seen.add(jti)
        return True


# ---------------------------------------------------------------------------
# M4 — cross-endpoint DPoP replay: fail closed when endpoint_uri is unset
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_dpop_proof_rejected_when_endpoint_uri_unset():
    """A voluntarily-presented DPoP proof (require_dpop=False, endpoint_uri=None)
    must be REJECTED — htu cannot be validated, so accepting it would permit a
    proof captured for another endpoint to be replayed here (RFC 9449 §4.3)."""
    key = _hmac_key()
    ec_key = _ec_keypair()
    engine = AuthEngine(
        require_dpop=False,
        jwks=_hmac_jwks(key),
        endpoint_uri=None,
        require_cnf_binding=False,  # isolate the endpoint_uri gate from the cnf gate
    )
    token = _signed_jwt(_now_claims(), key)  # no cnf.jkt
    proof = _dpop_proof(token, ec_key)  # otherwise-valid proof
    req = _auth_req(token, scheme="DPoP", dpop=proof)
    with pytest.raises(AuthenticationError, match="endpoint_uri|htu"):
        await engine.on_request(make_ctx(), req)


@pytest.mark.asyncio
async def test_dpop_voluntary_proof_accepted_when_endpoint_uri_set():
    """Positive control: the same voluntary proof IS accepted once endpoint_uri
    is configured — the M4 fix rejects only the un-validatable (unset) case, it
    does not disable voluntary DPoP."""
    key = _hmac_key()
    ec_key = _ec_keypair()
    engine = AuthEngine(
        require_dpop=False,
        jwks=_hmac_jwks(key),
        endpoint_uri=_ENDPOINT,
        require_cnf_binding=False,
    )
    token = _signed_jwt(_now_claims(), key)
    proof = _dpop_proof(token, ec_key, htu=_ENDPOINT)
    new_ctx = await engine.on_request(make_ctx(), _auth_req(token, scheme="DPoP", dpop=proof))
    assert new_ctx.user_id == "user-1"


# ---------------------------------------------------------------------------
# joserfc/HS* hardening — HS* only when the JWKS is exclusively `oct`
# ---------------------------------------------------------------------------


def test_regression_hs_algs_dropped_when_jwks_has_asymmetric_keys():
    """An asymmetric (EC) JWKS must yield an access-token allowlist with NO HS*
    algorithms — otherwise an attacker could present an HS256 token verified
    against the EC public key (RS/HS confusion)."""
    ec_key = _ec_keypair()
    engine = AuthEngine(require_dpop=False, jwks={"keys": [_public_jwk(ec_key)]})
    assert "HS256" not in engine._access_token_algs
    assert "HS384" not in engine._access_token_algs
    assert "HS512" not in engine._access_token_algs
    # Asymmetric algorithms remain available.
    assert "ES256" in engine._access_token_algs


def test_regression_hs_algs_dropped_when_jwks_mixes_oct_and_asymmetric():
    """A mixed JWKS (oct + EC) — the exact RS/HS-confusion setup — must also drop
    HS*: HS is allowed only when the key set is EXCLUSIVELY symmetric."""
    oct_key = _hmac_key()
    ec_key = _ec_keypair()
    jwks = {"keys": [oct_key.as_dict(), _public_jwk(ec_key)]}
    engine = AuthEngine(require_dpop=False, jwks=jwks)
    assert "HS256" not in engine._access_token_algs


def test_hs_algs_present_when_jwks_is_oct_only():
    """Backward compatible: an exclusively-`oct` JWKS keeps HS* available, so an
    operator's symmetric deployment still verifies HS256 tokens."""
    engine = AuthEngine(require_dpop=False, jwks=_hmac_jwks(_hmac_key()))
    assert "HS256" in engine._access_token_algs
    assert "HS384" in engine._access_token_algs
    assert "HS512" in engine._access_token_algs


@pytest.mark.asyncio
async def test_oct_only_jwks_still_verifies_hs256_token():
    """End-to-end: an HS256 access token still passes under an oct-only JWKS."""
    key = _hmac_key()
    engine = AuthEngine(require_dpop=False, jwks=_hmac_jwks(key))
    token = _signed_jwt(_now_claims(), key)
    new_ctx = await engine.on_request(make_ctx(), _auth_req(token, scheme="Bearer"))
    assert new_ctx.user_id == "user-1"


# ---------------------------------------------------------------------------
# M5 — pluggable DPoP jti replay store (shared-store injection)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_dpop_jti_store_pluggable_and_consulted():
    """An injected shared jti store must be used for DPoP replay detection
    instead of the per-process _JTICache, and a proof replayed against that
    shared store (as a second worker would see it) must be rejected."""
    fake = _FakeSharedJTIStore()
    key = _hmac_key()
    ec_key = _ec_keypair()
    engine = AuthEngine(
        require_dpop=True,
        jwks=_hmac_jwks(key),
        endpoint_uri=_ENDPOINT,
        require_cnf_binding=False,
        dpop_jti_store=fake,
    )
    # The engine must not fall back to its internal in-memory cache for DPoP jti.
    assert engine._dpop_jti_cache is fake

    token = _signed_jwt(_now_claims(), key)
    dpop_jti = str(uuid.uuid4())
    proof = _dpop_proof(token, ec_key, htu=_ENDPOINT, jti=dpop_jti)
    await engine.on_request(make_ctx(), _auth_req(token, scheme="DPoP", dpop=proof))

    # The injected store was consulted with the proof's jti.
    assert dpop_jti in [c[0] for c in fake.calls]

    # A replay of the same jti (as a different worker sharing the store would see)
    # is detected through the injected store.
    token2 = _signed_jwt(_now_claims(), key)
    proof2 = _dpop_proof(token2, ec_key, htu=_ENDPOINT, jti=dpop_jti)
    with pytest.raises(AuthenticationError, match="DPoP JTI replayed"):
        await engine.on_request(make_ctx(), _auth_req(token2, scheme="DPoP", dpop=proof2))


@pytest.mark.asyncio
async def test_dpop_jti_store_defaults_to_in_memory_cache():
    """Backward compatible: with no injected store the engine uses its own
    in-memory _JTICache and startup does not raise (only warns)."""
    from mcp_armor.engines.auth import _JTICache

    engine = AuthEngine(
        require_dpop=True,
        jwks=_hmac_jwks(_hmac_key()),
        endpoint_uri=_ENDPOINT,
    )
    assert isinstance(engine._dpop_jti_cache, _JTICache)
    assert engine._dpop_jti_store_is_shared is False
    await engine.on_startup()  # must not raise (emits the multi-worker warning)


@pytest.mark.asyncio
async def test_dpop_jti_shared_store_suppresses_startup_warning(caplog):
    """When a shared store is injected, on_startup must NOT emit the per-process
    warning; with the default in-memory store it must."""
    import logging

    ec_shared = AuthEngine(
        require_dpop=True,
        jwks=_hmac_jwks(_hmac_key()),
        endpoint_uri=_ENDPOINT,
        dpop_jti_store=_FakeSharedJTIStore(),
    )
    with caplog.at_level(logging.WARNING, logger="mcp_armor.engines.auth"):
        await ec_shared.on_startup()
    assert "per-process in-memory store" not in caplog.text

    caplog.clear()
    default_engine = AuthEngine(
        require_dpop=True,
        jwks=_hmac_jwks(_hmac_key()),
        endpoint_uri=_ENDPOINT,
    )
    with caplog.at_level(logging.WARNING, logger="mcp_armor.engines.auth"):
        await default_engine.on_startup()
    assert "per-process in-memory store" in caplog.text
