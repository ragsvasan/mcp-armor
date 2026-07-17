"""T1 — Improper Authentication: JWT signature, JTI replay, session binding, DPoP (RFC 9449)."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import threading
import time
from typing import TYPE_CHECKING, Any, Protocol, cast

from ..context import CoSAIContext
from ..exceptions import AuthenticationError
from ..types import MCPRequest, MCPResponse

if TYPE_CHECKING:
    from joserfc.jwk import KeySetSerialization

log = logging.getLogger(__name__)

# Asymmetric-only algorithms allowed for DPoP (RFC 9449 §4.2)
_DPOP_ALLOWED_ALGS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)

# Symmetric HMAC algorithms — permitted for access-token verification ONLY when
# the configured JWKS is exclusively `oct` keys (see
# AuthEngine._compute_access_token_algs). Allowing HS* while an asymmetric key is
# present enables RS/HS algorithm-confusion (signing an HS256 token with an
# RSA/EC *public* key as the HMAC secret) and needlessly exposes the joserfc
# empty-`oct`-key HMAC surface on the asymmetric verification path.
_HS_ALGS = frozenset({"HS256", "HS384", "HS512"})

# F8 fix: explicit algorithm allowlists. Never rely on the JWT library's default
# — pin them so a downgraded/regressed joserfc cannot accept `alg:none`. The
# access-token allowlist is derived per-instance from the JWKS key types
# (AuthEngine._compute_access_token_algs); HS* is added only for an
# exclusively-`oct` JWKS. The DPoP list is always asymmetric-only.
_DPOP_ALGS_LIST: list[str] = sorted(_DPOP_ALLOWED_ALGS)

# Minimum RSA modulus bits (NIST SP 800-131A)
_MIN_RSA_BITS = 2048


class _JTICache:
    """
    Thread-safe JTI replay cache with time-based eviction.

    Entries expire when the associated token expires (its `exp` claim).
    If the cache is full of unexpired entries, new tokens are rejected
    rather than silently evicting and re-allowing replayed JTIs.
    """

    def __init__(self, maxsize: int) -> None:
        self._entries: dict[str, float] = {}  # jti → expiry Unix timestamp
        self._maxsize = maxsize
        self._lock = threading.Lock()

    def check_and_add(self, jti: str, exp: float) -> bool:
        """
        Return True if jti is new and was added.
        Return False if jti was already seen (replay).
        Raise AuthenticationError if cache is full of unexpired entries.
        """
        with self._lock:
            now = time.time()
            expired = [k for k, v in self._entries.items() if v <= now]
            for k in expired:
                del self._entries[k]

            if jti in self._entries:
                return False

            if len(self._entries) >= self._maxsize:
                raise AuthenticationError(
                    "JTI cache full — cannot accept new tokens without risking "
                    "replay eviction. Reduce token TTL or increase jti_cache_size."
                )

            self._entries[jti] = exp
            return True


class JTIReplayStore(Protocol):
    """
    Pluggable replay store for DPoP proof ``jti`` values (M5).

    One method: atomically test-and-set with a TTL. Implementations may back this
    with any shared medium (e.g. Redis) so multi-worker / multi-node deployments
    share a single replay view and a proof replayed to a different worker within
    the ``iat`` window is still detected. The default in-process ``_JTICache``
    satisfies this Protocol.
    """

    def check_and_add(self, jti: str, exp: float) -> bool:
        """
        Register ``jti`` with expiry ``exp`` (Unix seconds).

        Return True if ``jti`` was previously unseen (added now). Return False if
        ``jti`` was already present within its TTL (a replay). May raise
        ``AuthenticationError`` if the store cannot safely accept the entry.
        """
        ...


def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _parse_jwt_header(token: str) -> dict[str, Any]:
    """Decode the JWT header without signature verification."""
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthenticationError("Malformed JWT: expected 3 dot-separated parts")
    try:
        return cast(dict[str, Any], json.loads(_b64url_decode(parts[0])))
    except Exception as exc:
        raise AuthenticationError("Cannot decode JWT header") from exc


def _import_jwk(jwk_data: dict[str, Any]) -> Any:
    """Import a single JWK dict into a joserfc key object."""
    from joserfc.jwk import ECKey, OctKey, RSAKey

    kty = jwk_data.get("kty")
    if kty == "EC":
        return ECKey.import_key(jwk_data)
    if kty == "RSA":
        return RSAKey.import_key(jwk_data)
    if kty == "oct":
        return OctKey.import_key(jwk_data)
    raise AuthenticationError(f"Unsupported JWK kty: {kty!r}")


def _jwk_thumbprint(jwk_data: dict[str, Any]) -> str:
    """
    RFC 7638 JWK Thumbprint (SHA-256, base64url, no padding).
    Only required key members in lexicographic order, no spaces.
    """
    kty = jwk_data.get("kty")
    if kty == "EC":
        required = {"crv", "kty", "x", "y"}
    elif kty == "RSA":
        required = {"e", "kty", "n"}
    elif kty == "oct":
        required = {"k", "kty"}
    else:
        raise AuthenticationError(f"Cannot compute thumbprint for kty={kty!r}")
    body = json.dumps(
        {k: jwk_data[k] for k in sorted(required) if k in jwk_data},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return _b64url_encode(hashlib.sha256(body).digest())


def _check_rsa_key_size(jwk_data: dict[str, Any]) -> None:
    """Reject RSA keys below the minimum modulus size (NIST SP 800-131A)."""
    n_b64 = jwk_data.get("n", "")
    if not n_b64:
        return
    try:
        modulus_bits = len(_b64url_decode(n_b64)) * 8
    except Exception as exc:
        # C2 fix: a key whose modulus cannot be decoded is malformed — fail
        # closed (reject) rather than silently skipping the NIST size floor,
        # which let an attacker bypass the check with a corrupt `n`.
        raise AuthenticationError(
            "DPoP RSA key modulus is malformed — cannot verify key size (NIST SP 800-131A)"
        ) from exc
    if modulus_bits < _MIN_RSA_BITS:
        raise AuthenticationError(
            f"DPoP RSA key is {modulus_bits} bits — minimum is {_MIN_RSA_BITS} (NIST SP 800-131A)"
        )


def _require_int_claim(claims: dict[str, Any], key: str) -> None:
    val = claims.get(key)
    if val is not None and not isinstance(val, (int, float)):
        raise AuthenticationError(f"JWT {key!r} claim must be numeric, got {type(val).__name__!r}")


class AuthEngine:
    """
    Validates bearer/DPoP tokens on every MCP request.

    Covers:
    - T1-001: Missing Authorization header
    - T1-002: Token replay (JTI cache, time-based eviction)
    - T1-003: Cross-session token reuse (sid/session_id claim binding)
    - T1-004: DPoP proof validation (RFC 9449) — typ, alg, iat freshness,
               htu/htm binding, JTI replay, ath access-token hash,
               cnf.jkt thumbprint binding

    Configuration
    -------------
    jwks : dict
        JWKS JSON ({"keys": [...]}) or single JWK for access-token signature
        verification. Required — the engine raises at startup if absent.
    require_dpop : bool
        If True, every request must include a DPoP proof header. Additionally,
        if an access token's `cnf.jkt` claim is present, DPoP is required
        regardless of this flag.
    require_cnf_binding : bool
        If True (default), whenever DPoP is in force for a request — either
        because ``require_dpop=True`` or because the request carries a DPoP
        proof — the access token MUST be sender-constrained, i.e. carry a
        ``cnf.jkt`` claim (RFC 9449 §4.3). A DPoP proof presented against a
        token without ``cnf.jkt`` is never bound to that token, so a stolen
        non-bound token could be replayed with any attacker-minted proof. The
        engine fails closed in that case. Set ``False`` only to accept
        unbound access tokens under DPoP (not recommended — defeats the
        sender-constraint guarantee).
    endpoint_uri : str | None
        The canonical URI of this MCP endpoint, used for DPoP ``htu`` binding.
        Required when require_dpop=True. Because a DPoP proof may be presented
        voluntarily even when require_dpop=False, any request carrying a DPoP
        proof is rejected when this is unset (M4: ``htu`` cannot be validated, so
        the engine fails closed rather than accept a possible cross-endpoint
        replay).
    dpop_jti_store : JTIReplayStore | None
        Optional shared store for DPoP proof ``jti`` replay detection (M5). When
        None (default) a per-process in-memory cache is used — correct for a
        single worker, but multi-worker / multi-node deployments must inject a
        shared store (e.g. a Redis-backed ``check_and_add`` with TTL) so a proof
        replayed to a different worker is still detected. ``on_startup`` emits a
        warning when the in-memory default is in use.
    """

    def __init__(
        self,
        require_dpop: bool = True,
        require_jti: bool = True,
        jti_cache_size: int = 10_000,
        token_expiry_max_secs: int = 3600,
        jwks: dict[str, Any] | None = None,
        issuer: str | None = None,
        audience: str | None = None,
        dpop_max_age_secs: int = 30,
        dpop_future_skew_secs: int = 5,
        endpoint_uri: str | None = None,
        require_cnf_binding: bool = True,
        dpop_jti_store: JTIReplayStore | None = None,
    ) -> None:
        self._require_dpop = require_dpop
        self._require_cnf_binding = require_cnf_binding
        self._require_jti = require_jti
        self._token_expiry_max_secs = token_expiry_max_secs
        self._issuer = issuer
        self._audience = audience
        self._dpop_max_age_secs = dpop_max_age_secs
        self._dpop_future_skew_secs = dpop_future_skew_secs
        self._endpoint_uri = endpoint_uri
        self._jti_cache = _JTICache(jti_cache_size)
        # M5: the DPoP jti replay store is pluggable. Default to the per-process
        # in-memory _JTICache (backward compatible); a multi-worker / multi-node
        # deployment injects a shared store (Redis-backed check_and_add with a
        # TTL) so a proof replayed to a different worker is still detected.
        # on_startup warns when the in-memory default is in use.
        self._dpop_jti_store_is_shared = dpop_jti_store is not None
        self._dpop_jti_cache: JTIReplayStore = (
            dpop_jti_store if dpop_jti_store is not None else _JTICache(jti_cache_size)
        )
        self._key_set = self._load_keys(jwks) if jwks is not None else None
        # HS/RS hardening: HS* is allowed for access tokens only when the JWKS is
        # exclusively `oct` (see _compute_access_token_algs).
        self._access_token_algs: list[str] = (
            self._compute_access_token_algs(jwks) if jwks is not None else list(_DPOP_ALGS_LIST)
        )

    def _load_keys(self, jwks: dict[str, Any]) -> Any:
        from joserfc.jwk import KeySet

        if "keys" in jwks:
            return KeySet.import_key_set(cast("KeySetSerialization", jwks))
        return _import_jwk(jwks)

    @staticmethod
    def _compute_access_token_algs(jwks: dict[str, Any]) -> list[str]:
        """
        Derive the access-token algorithm allowlist from the configured JWKS.

        HS256/384/512 are included ONLY when every key is a symmetric ``oct`` key.
        The moment any asymmetric key (RSA/EC/OKP) is present, HS* is dropped so
        an attacker cannot present an HS256 token verified against an asymmetric
        *public* key (RS/HS confusion), and the joserfc empty-``oct``-key HMAC
        surface is kept off the asymmetric path. Asymmetric algorithms are always
        allowed; an empty or unknown-``kty`` JWKS yields the asymmetric-only list
        (HS* dropped — fail safe).
        """
        if "keys" in jwks:
            key_dicts = jwks.get("keys") or []
        else:
            key_dicts = [jwks]
        ktys = {kd.get("kty") for kd in key_dicts if isinstance(kd, dict)}
        algs = set(_DPOP_ALLOWED_ALGS)
        if ktys == {"oct"}:
            algs |= _HS_ALGS
        return sorted(algs)

    # ------------------------------------------------------------------
    # Access-token verification
    # ------------------------------------------------------------------

    def _verify_access_token(self, token: str) -> dict[str, Any]:
        """Verify JWT signature and all standard claims. Fails closed."""
        if self._key_set is None:
            raise AuthenticationError(
                "No JWKS configured — refusing to accept tokens. "
                "Set jwks= on AuthEngine to enable JWT verification."
            )

        try:
            from joserfc import jwt

            # F8 fix: pin the algorithm allowlist explicitly — do not trust
            # the library default.
            obj = jwt.decode(token, self._key_set, algorithms=self._access_token_algs)
            claims: dict[str, Any] = obj.claims
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError("JWT verification failed") from exc

        now = time.time()

        # Type-check numeric time claims before comparison
        _require_int_claim(claims, "exp")
        _require_int_claim(claims, "iat")
        _require_int_claim(claims, "nbf")

        exp = claims.get("exp")
        if exp is None:
            raise AuthenticationError("JWT missing exp claim")
        if now > exp:
            raise AuthenticationError("JWT has expired")

        nbf = claims.get("nbf")
        if nbf is not None and now < nbf:
            raise AuthenticationError("JWT not yet valid (nbf)")

        iat = claims.get("iat")
        if iat is not None and (now - iat) > self._token_expiry_max_secs:
            raise AuthenticationError(
                f"JWT issued too long ago (max {self._token_expiry_max_secs}s)"
            )

        # iss and aud enforced unconditionally (not gated on key presence)
        if self._issuer and claims.get("iss") != self._issuer:
            raise AuthenticationError("JWT issuer mismatch")

        if self._audience:
            aud = claims.get("aud")
            if isinstance(aud, str):
                aud = [aud]
            if not aud or self._audience not in aud:
                raise AuthenticationError("JWT audience mismatch")

        jti = claims.get("jti")
        if jti is None:
            # F5 fix: a token without jti cannot be replay-tracked. Fail
            # closed by default (mirrors the DPoP path which already raises
            # on missing jti). Operators that deliberately accept jti-less
            # tokens must opt out via require_jti=False.
            if self._require_jti:
                raise AuthenticationError(
                    "JWT missing jti claim — replay protection requires a unique "
                    "token identifier (T1-002). Set require_jti=False only if the "
                    "issuer cannot mint jti and replay risk is accepted."
                )
        else:
            if not self._jti_cache.check_and_add(jti, float(exp)):
                raise AuthenticationError("JWT JTI replayed — token replay attack detected")

        return claims

    # ------------------------------------------------------------------
    # DPoP proof validation (RFC 9449)
    # ------------------------------------------------------------------

    def _verify_dpop(
        self,
        proof: str,
        access_token: str,
        access_token_claims: dict[str, Any],
        http_method: str,
    ) -> None:
        """
        Validate a DPoP proof JWT per RFC 9449.

        Checks: typ=dpop+jwt, asymmetric alg, no private key embedded, key strength,
        embedded JWK, iat freshness (asymmetric window), htu/htm binding,
        jti replay, ath binding, cnf.jkt thumbprint binding against access token.
        """
        header = _parse_jwt_header(proof)

        if header.get("typ") != "dpop+jwt":
            raise AuthenticationError("DPoP proof missing typ=dpop+jwt")

        alg = header.get("alg", "")
        if alg not in _DPOP_ALLOWED_ALGS:
            raise AuthenticationError(
                f"DPoP proof uses disallowed algorithm {alg!r} — must be asymmetric"
            )

        jwk_data = header.get("jwk")
        if not jwk_data or not isinstance(jwk_data, dict):
            raise AuthenticationError("DPoP proof missing embedded JWK in header")

        if "d" in jwk_data:
            raise AuthenticationError("DPoP proof embeds a private key — protocol violation")

        if jwk_data.get("kty") == "RSA":
            _check_rsa_key_size(jwk_data)

        try:
            proof_key = _import_jwk(jwk_data)
            from joserfc import jwt

            # F8 fix: pin to the asymmetric DPoP algorithm allowlist (already
            # validated against the header above; pinning here closes the
            # library-default gap if joserfc ever regresses).
            obj = jwt.decode(proof, proof_key, algorithms=_DPOP_ALGS_LIST)
            claims = obj.claims
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError("DPoP proof signature invalid") from exc

        _require_int_claim(claims, "iat")
        now = time.time()

        iat = claims.get("iat")
        if iat is None:
            raise AuthenticationError("DPoP proof missing iat claim")
        # Asymmetric window: past is bounded by dpop_max_age_secs, future by skew
        if (now - iat) > self._dpop_max_age_secs:
            raise AuthenticationError(f"DPoP proof iat too old (max {self._dpop_max_age_secs}s)")
        if (iat - now) > self._dpop_future_skew_secs:
            raise AuthenticationError(
                f"DPoP proof iat too far in the future (max skew {self._dpop_future_skew_secs}s)"
            )

        # M4: htu binding is mandatory. A voluntarily-presented proof
        # (require_dpop=False, endpoint_uri unset) previously skipped this check,
        # letting an intermediary replay a proof captured for another endpoint
        # against this instance within the iat window (RFC 9449 §4.3 cross-
        # endpoint replay). If endpoint_uri is not configured we cannot validate
        # htu, so fail closed rather than silently accept.
        if self._endpoint_uri is None:
            raise AuthenticationError(
                "DPoP proof presented but this endpoint's URI is not configured — "
                "cannot validate the htu binding (RFC 9449 §4.3), so the proof may "
                "be a cross-endpoint replay. Refusing. Set endpoint_uri on AuthEngine."
            )
        htu = claims.get("htu", "")
        if htu.rstrip("/") != self._endpoint_uri.rstrip("/"):
            raise AuthenticationError(
                f"DPoP htu mismatch: got {htu!r}, expected {self._endpoint_uri!r}"
            )

        htm = claims.get("htm", "")
        if htm.upper() != http_method.upper():
            raise AuthenticationError(f"DPoP htm mismatch: got {htm!r}, expected {http_method!r}")

        jti = claims.get("jti")
        if not jti:
            raise AuthenticationError("DPoP proof missing jti")
        dpop_exp = now + self._dpop_max_age_secs
        if not self._dpop_jti_cache.check_and_add(jti, dpop_exp):
            raise AuthenticationError("DPoP JTI replayed — proof replay attack detected")

        # ath = base64url(sha256(ASCII(access_token)))
        expected_ath = _b64url_encode(hashlib.sha256(access_token.encode("ascii")).digest())
        if claims.get("ath") != expected_ath:
            raise AuthenticationError("DPoP ath binding mismatch — token/proof not paired")

        # cnf.jkt binding (RFC 9449 §6): proof key thumbprint must match access token's cnf.jkt
        cnf = access_token_claims.get("cnf")
        if cnf and isinstance(cnf, dict):
            expected_jkt = cnf.get("jkt")
            if expected_jkt:
                actual_jkt = _jwk_thumbprint(jwk_data)
                if actual_jkt != expected_jkt:
                    raise AuthenticationError(
                        "DPoP key thumbprint does not match access token cnf.jkt — "
                        "sender-constrained token presented with wrong key"
                    )

    # ------------------------------------------------------------------
    # Session binding (T1-003)
    # ------------------------------------------------------------------

    def _check_session_binding(self, claims: dict[str, Any], session_id: str) -> None:
        """Enforce that a token with a sid/session_id claim matches the current session."""
        sid = claims.get("sid") or claims.get("session_id")
        if sid and sid != session_id:
            raise AuthenticationError(
                "Token session binding mismatch (T1-003) — token bound to a different session"
            )

    # ------------------------------------------------------------------
    # Lifecycle hooks
    # ------------------------------------------------------------------

    async def on_startup(self) -> None:
        if self._key_set is None:
            raise ValueError(
                "AuthEngine: jwks= is required. Configure a JWKS for JWT verification. "
                "Running without a signing key is not allowed in a security middleware."
            )
        if self._require_dpop and self._endpoint_uri is None:
            raise ValueError(
                "AuthEngine: require_dpop=True requires endpoint_uri to be set "
                "(needed for DPoP htu binding)."
            )
        # M5: the default DPoP jti replay store is per-process. Warn operators
        # that multi-worker / multi-node deployments need a shared store, since a
        # proof replayed to a different worker within the iat window would
        # otherwise go undetected (RFC 9449 §11.1).
        if not self._dpop_jti_store_is_shared:
            log.warning(
                "AuthEngine: DPoP jti replay cache is a per-process in-memory store. "
                "Under multiple workers (uvicorn --workers N) or multiple nodes/pods a "
                "captured DPoP proof replayed to a different worker within the iat "
                "window is NOT detected (RFC 9449 §11.1). For multi-worker / multi-node "
                "deployments inject a shared store via dpop_jti_store= (e.g. a "
                "Redis-backed check_and_add with TTL=dpop_max_age_secs), implement an "
                "RFC 9449 §8 server nonce, or pin the deployment to a single worker."
            )

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        auth_header = req.raw_headers.get("authorization", "")

        dpop_proof = req.raw_headers.get("dpop", "")

        # RFC 6750 / RFC 9449: parse scheme and token correctly
        parts = auth_header.split(None, 1)
        if len(parts) != 2:
            raise AuthenticationError(
                "Missing or malformed Authorization header — "
                "expected 'Bearer <token>' or 'DPoP <token>'"
            )
        scheme, access_token = parts[0].lower(), parts[1].strip()

        if scheme not in {"bearer", "dpop"}:
            raise AuthenticationError(
                f"Unsupported Authorization scheme {parts[0]!r} — expected 'Bearer' or 'DPoP'"
            )

        if not access_token:
            raise AuthenticationError("Authorization header present but token is empty")

        # RFC 9449 §7.1: if DPoP proof is present, scheme must be DPoP
        if dpop_proof and scheme == "bearer":
            raise AuthenticationError(
                "DPoP proof header present but Authorization scheme is Bearer — "
                "use 'Authorization: DPoP <token>' when sending a DPoP proof (RFC 9449 §7.1)"
            )

        if self._require_dpop:
            if scheme != "dpop":
                raise AuthenticationError("DPoP required but Authorization scheme is not 'DPoP'")
            if not dpop_proof:
                raise AuthenticationError("DPoP required but DPoP proof header is absent")

        claims = self._verify_access_token(access_token)

        # T1-003: session binding via sid claim
        self._check_session_binding(claims, ctx.session_id)

        # If access token is sender-constrained (cnf.jkt present), DPoP is mandatory
        cnf = claims.get("cnf")
        cnf_jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
        if cnf_jkt and not dpop_proof:
            raise AuthenticationError(
                "Access token is sender-constrained (cnf.jkt) — DPoP proof is required "
                "(RFC 9449 §7.1)"
            )

        # RFC 9449 §4.3: when DPoP is in force — either required, or a proof was
        # presented — the access token MUST be sender-constrained (carry cnf.jkt).
        # Without it the DPoP proof is never bound to the token (_verify_dpop's
        # cnf.jkt thumbprint check only fires when cnf.jkt is present), so a
        # stolen non-bound token could be replayed with any attacker-minted valid
        # proof. Fail closed unless the operator explicitly opts out.
        if self._require_cnf_binding and (self._require_dpop or dpop_proof) and not cnf_jkt:
            raise AuthenticationError(
                "DPoP is in force but the access token is not sender-constrained "
                "(missing cnf.jkt) — the DPoP proof key cannot be bound to the "
                "token, permitting replay of a stolen token (RFC 9449 §4.3). "
                "Issue sender-constrained tokens carrying cnf.jkt, or set "
                "require_cnf_binding=False to accept unbound tokens (not recommended)."
            )

        if dpop_proof:
            # MCP always uses POST — never trust a client header for the HTTP method
            self._verify_dpop(dpop_proof, access_token, claims, http_method="POST")

        sub = claims.get("sub") or claims.get("client_id", "")

        # FIX[16]: conflicting tenant claims are a privilege-escalation vector —
        # reject tokens that carry both tenant_id and tid with different values.
        tenant_id = claims.get("tenant_id")
        tid = claims.get("tid")
        if tenant_id is not None and tid is not None and tenant_id != tid:
            raise AuthenticationError(
                "Conflicting tenant claims: tenant_id and tid present with different values"
            )
        tenant = tenant_id or tid

        # Extract OAuth scopes for T2 AuthzEngine — stored in context, never logged raw
        raw_scope = claims.get("scope", "")
        raw_scopes_list = claims.get("scopes")
        if isinstance(raw_scopes_list, list):
            scopes: tuple[str, ...] = tuple(str(s) for s in raw_scopes_list)
        elif isinstance(raw_scope, str) and raw_scope:
            scopes = tuple(raw_scope.split())
        else:
            scopes = ()

        return ctx.with_user(sub, tenant).with_scopes(scopes)

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
