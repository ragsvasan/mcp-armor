"""CoSAI v2.0 P2 parity (ported from cosai-mcp): requestState sealing (SD-03),
server-held handles (SD-01), request-envelope validation (TN-04), _meta
reconciliation (SD-02) and W3C trace context (LO-03)."""
from __future__ import annotations

import base64
import hashlib
from typing import Any

import pytest

from mcp_armor.explicit_state import (
    HandleError,
    HandleRegistry,
    RequestStateSealer,
    StateVerificationError,
    request_fingerprint,
)
from mcp_armor.mcp_protocol import (
    META_CLIENT_CAPABILITIES,
    META_CLIENT_INFO,
    META_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
    encode_header_value,
    request_metadata_headers,
    with_request_meta,
)
from mcp_armor.request_envelope import (
    AuthenticatedPrincipal,
    MetaTrustError,
    RequestMetadataError,
    reconcile_meta,
    validate_request_metadata,
)
from mcp_armor.tracecontext import (
    parse_traceparent,
    preserve_client_trace,
    sanitize_baggage,
)

_K1 = hashlib.sha256(b"test-key-1").digest()
_K2 = hashlib.sha256(b"test-key-2").digest()


class _Clock:
    def __init__(self, t: float = 1_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


PARAMS = {"name": "book", "arguments": {"when": "tomorrow"}}


RID = request_fingerprint("tools/call", PARAMS)


def _sealer(**kw: Any) -> RequestStateSealer:
    kw.setdefault("audience", "https://mcp.example/mcp")
    return RequestStateSealer({"k1": _K1}, active_kid="k1", **kw)


class TestRequestStateSealer:
    def test_round_trip(self) -> None:
        s = _sealer()
        token = s.seal({"step": 2}, tenant="t", principal="alice", request_id=RID)
        assert s.open(token, tenant="t", principal="alice", request_id=RID) == {"step": 2}

    def test_opaque_to_client(self) -> None:
        token = _sealer().seal({"secret": "top-secret-value"}, tenant="t", principal="alice",
                               request_id=RID)
        assert "top-secret-value" not in token
        blob = token.split(".", 2)[2]
        assert b"top-secret" not in base64.urlsafe_b64decode(blob + "==")

    @pytest.mark.parametrize("mutate", [
        lambda t: t[:-2] + ("A" if t[-2] != "A" else "B") + t[-1],      # flip ciphertext
        lambda t: t.replace("v1.", "v2.", 1),                          # wrong format
        lambda t: t.replace(".k1.", ".k9.", 1),                        # unknown key id
        lambda t: "not-a-state",
        lambda t: 12345,
        lambda t: "v1.k1." + "A" * 5,                                  # too short
    ])
    def test_tampering_rejected(self, mutate: Any) -> None:
        s = _sealer()
        token = s.seal({"step": 2}, tenant="t", principal="alice", request_id=RID)
        with pytest.raises(StateVerificationError):
            s.open(mutate(token), tenant="t", principal="alice", request_id=RID)

    def test_other_principal_rejected(self) -> None:
        s = _sealer()
        token = s.seal({}, tenant="t", principal="alice", request_id=RID)
        with pytest.raises(StateVerificationError):
            s.open(token, tenant="t", principal="mallory", request_id=RID)

    def test_other_request_rejected(self) -> None:
        s = _sealer()
        token = s.seal({}, tenant="t", principal="alice", request_id=RID)
        other = request_fingerprint("tools/call", {"name": "book",
                                                   "arguments": {"when": "never"}})
        with pytest.raises(StateVerificationError):
            s.open(token, tenant="t", principal="alice", request_id=other)

    def test_retry_params_do_not_change_fingerprint(self) -> None:
        retry = {**PARAMS, "requestState": "x", "inputResponses": {"q": {}},
                 "_meta": {META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION}}
        assert request_fingerprint("tools/call", retry) == RID

    def test_expiry(self) -> None:
        clock = _Clock()
        s = _sealer(clock=clock, default_ttl_seconds=60)
        token = s.seal({}, tenant="t", principal="alice", request_id=RID)
        clock.t += 61
        with pytest.raises(StateVerificationError):
            s.open(token, tenant="t", principal="alice", request_id=RID)

    def test_single_use(self) -> None:
        s = _sealer(single_use=True)
        token = s.seal({}, tenant="t", principal="alice", request_id=RID)
        s.open(token, tenant="t", principal="alice", request_id=RID)
        with pytest.raises(StateVerificationError):
            s.open(token, tenant="t", principal="alice", request_id=RID)

    def test_key_rotation(self) -> None:
        old = RequestStateSealer({"k1": _K1}, active_kid="k1", audience="aud")
        token = old.seal({"a": 1}, tenant="t", principal="alice", request_id=RID)
        rotated = RequestStateSealer({"k1": _K1, "k2": _K2},
                                     active_kid="k2", audience="aud")
        assert rotated.open(token, tenant="t", principal="alice", request_id=RID) == {"a": 1}
        assert rotated.seal({}, tenant="t", principal="alice", request_id=RID).startswith("v1.k2.")
        retired = RequestStateSealer({"k2": _K2}, active_kid="k2", audience="aud")
        with pytest.raises(StateVerificationError):
            retired.open(token, tenant="t", principal="alice", request_id=RID)

    def test_error_is_uninformative(self) -> None:
        s = _sealer()
        token = s.seal({}, tenant="t", principal="alice", request_id=RID)
        msgs = set()
        for bad in (token[:-3] + "AAA", token.replace("k1", "k9"), "junk"):
            try:
                s.open(bad, tenant="t", principal="alice", request_id=RID)
            except StateVerificationError as exc:
                msgs.add(str(exc))
        try:
            s.open(token, tenant="t", principal="mallory", request_id=RID)
        except StateVerificationError as exc:
            msgs.add(str(exc))
        assert len(msgs) == 1

    @pytest.mark.parametrize("kwargs", [
        {"keys": {}, "active_kid": "k1"},
        {"keys": {"k1": b"short"}, "active_kid": "k1"},
        {"keys": {"k1": _K1}, "active_kid": "k2"},
        {"keys": {"bad kid!": _K1}, "active_kid": "bad kid!"},
    ])
    def test_config_validation(self, kwargs: dict[str, Any]) -> None:
        with pytest.raises(ValueError):
            RequestStateSealer(kwargs["keys"], active_kid=kwargs["active_kid"],
                               audience="aud")

    def test_generated_keys_are_random_256_bit(self) -> None:
        a, b = RequestStateSealer.generate_key(), RequestStateSealer.generate_key()
        assert len(a) == 32 and a != b


class TestHandleRegistry:
    def test_mint_is_opaque_and_unguessable(self) -> None:
        reg = HandleRegistry()
        handles = {reg.mint(principal="alice", tenant="acme", kind="task", ttl_seconds=60)
                   for _ in range(200)}
        assert len(handles) == 200
        for h in handles:
            assert len(h) >= 43 and "alice" not in h and "acme" not in h

    def test_possession_is_not_authority(self) -> None:
        reg = HandleRegistry()
        h = reg.mint(principal="alice", tenant="acme", kind="task", ttl_seconds=60)
        assert reg.resolve(h, principal="alice", tenant="acme").principal == "alice"
        for principal, tenant in (("mallory", "acme"), ("alice", "evil-corp")):
            with pytest.raises(HandleError):
                reg.resolve(h, principal=principal, tenant=tenant)
        with pytest.raises(HandleError):
            reg.resolve(h, principal="alice", tenant="acme", kind="cursor")

    def test_unknown_expired_and_revoked_indistinguishable(self) -> None:
        clock = _Clock()
        reg = HandleRegistry(clock=clock)
        expired = reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=10)
        revoked = reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=100)
        reg.revoke(revoked, principal="a", tenant="t")
        clock.t += 11
        msgs = set()
        for h in ("unknown", expired, revoked, 42):
            with pytest.raises(HandleError) as ei:
                reg.resolve(h, principal="a", tenant="t")
            msgs.add(str(ei.value))
        assert len(msgs) == 1

    def test_revoke_principal_cancels_and_enumerates(self) -> None:
        cancelled: list[str] = []
        reg = HandleRegistry(on_revoke=lambda r: cancelled.append(r.handle))
        mine = [reg.mint(principal="alice", tenant="acme", kind="task", ttl_seconds=60)
                for _ in range(3)]
        other = reg.mint(principal="bob", tenant="acme", kind="task", ttl_seconds=60)
        assert {r.handle for r in reg.list_for_principal("alice")} == set(mine)
        revoked = reg.revoke_principal("alice")
        assert {r.handle for r in revoked} == set(mine) == set(cancelled)
        assert reg.list_for_principal("alice") == []
        for h in mine:
            with pytest.raises(HandleError):
                reg.resolve(h, principal="alice", tenant="acme")
        assert reg.resolve(other, principal="bob", tenant="acme")

    def test_bounds(self) -> None:
        reg = HandleRegistry(max_handles=2, max_handles_per_tenant=100, max_ttl_seconds=100)
        with pytest.raises(ValueError):
            reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=101)
        with pytest.raises(ValueError):
            reg.mint(principal="", tenant="t", kind="task", ttl_seconds=10)
        for _ in range(4):      # global cap 2; owner floor admits up to the 2x ceiling
            reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=10)
        with pytest.raises(RuntimeError):
            reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=10)


_META = {META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION, META_CLIENT_INFO: {"name": "c"},
         META_CLIENT_CAPABILITIES: {}}


def _request(method: str, params: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    params = with_request_meta(params, _META)
    headers = request_metadata_headers(method, params)
    return headers, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}


class TestEnvelopeValidation:
    def test_conforming_request_passes(self) -> None:
        h, b = _request("tools/call", {"name": "echo", "arguments": {}})
        assert validate_request_metadata(h, b) == MODERN_PROTOCOL_VERSION

    @pytest.mark.parametrize(("header", "value"), [
        ("Mcp-Method", "tools/list"),
        ("Mcp-Name", "admin_delete"),
        ("MCP-Protocol-Version", "2025-11-25"),
    ])
    def test_mismatch_is_32020(self, header: str, value: str) -> None:
        h, b = _request("tools/call", {"name": "echo", "arguments": {}})
        h[header] = value
        with pytest.raises(RequestMetadataError) as ei:
            validate_request_metadata(h, b)
        assert ei.value.code == -32020 and ei.value.http_status == 400

    @pytest.mark.parametrize("missing", ["Mcp-Method", "Mcp-Name", "MCP-Protocol-Version"])
    def test_missing_header_is_32020(self, missing: str) -> None:
        h, b = _request("tools/call", {"name": "echo", "arguments": {}})
        del h[missing]
        with pytest.raises(RequestMetadataError) as ei:
            validate_request_metadata(h, b)
        assert ei.value.code == -32020

    def test_unsupported_version_is_32022_with_supported_list(self) -> None:
        h, b = _request("tools/list", {})
        b["params"]["_meta"][META_PROTOCOL_VERSION] = "1900-01-01"
        h["MCP-Protocol-Version"] = "1900-01-01"
        with pytest.raises(RequestMetadataError) as ei:
            validate_request_metadata(h, b)
        err = ei.value.to_jsonrpc_error()
        assert err["code"] == -32022 and err["data"]["supported"] == [MODERN_PROTOCOL_VERSION]

    def test_missing_meta_is_32602(self) -> None:
        with pytest.raises(RequestMetadataError) as ei:
            validate_request_metadata({}, {"method": "tools/list", "params": {}})
        assert ei.value.code == -32602

    def test_base64_encoded_name_is_decoded(self) -> None:
        h, b = _request("tools/call", {"name": "résumé", "arguments": {}})
        assert h["Mcp-Name"].startswith("=?base64?")
        validate_request_metadata(h, b)

    def test_header_names_case_insensitive(self) -> None:
        h, b = _request("tools/list", {})
        validate_request_metadata({k.lower(): v for k, v in h.items()}, b)

    def test_x_mcp_param_headers_enforced(self) -> None:
        schemas = {"sql": {"type": "object", "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "limit": {"type": "integer", "x-mcp-header": "Limit"}}}}
        h, b = _request("tools/call", {"name": "sql",
                                       "arguments": {"region": "eu", "limit": 5}})
        h["Mcp-Param-Region"] = "eu"
        h["Mcp-Param-Limit"] = "5"
        validate_request_metadata(h, b, tool_schemas=schemas)
        h["Mcp-Param-Region"] = encode_header_value("us")
        with pytest.raises(RequestMetadataError):
            validate_request_metadata(h, b, tool_schemas=schemas)
        del h["Mcp-Param-Region"]
        with pytest.raises(RequestMetadataError):
            validate_request_metadata(h, b, tool_schemas=schemas)

    def test_control_chars_in_name_header_rejected(self) -> None:
        h, b = _request("tools/call", {"name": "echo", "arguments": {}})
        h["Mcp-Name"] = "echo\r\nX-Injected: 1"
        with pytest.raises(RequestMetadataError):
            validate_request_metadata(h, b)

    def test_scanner_probes_are_rejected_by_this_middleware(self) -> None:
        """The scanner's T07-004 (header≠body) and T07-005 (bogus version)
        requests are exactly what this validator rejects."""
        h, b = _request("tools/list", {})
        h["Mcp-Method"] = "tools/call"                         # T07-004-p1
        with pytest.raises(RequestMetadataError) as ei:
            validate_request_metadata(h, b)
        assert ei.value.code == -32020
        h, b = _request("tools/list", {"_meta": {META_PROTOCOL_VERSION: "1900-01-01"}})
        h["MCP-Protocol-Version"] = "1900-01-01"   # transport mirrors the body version
        with pytest.raises(RequestMetadataError) as ei:           # T07-005-p1
            validate_request_metadata(h, b)
        assert ei.value.code == -32022


ALICE = AuthenticatedPrincipal(subject="alice", tenant="acme", client_id="app-1",
                               scopes=frozenset({"read", "write"}))


class TestReconcileMeta:
    def test_consistent_or_absent_claims_pass(self) -> None:
        reconcile_meta(None, ALICE)
        reconcile_meta({**_META, "com.example/user": "alice", "com.example/tenant": "acme",
                        "com.example/scopes": ["read"], "com.example/is_admin": False}, ALICE)

    def test_client_info_is_display_only(self) -> None:
        reconcile_meta({META_CLIENT_INFO: {"name": "admin-console"}}, ALICE)

    @pytest.mark.parametrize("claim", [
        {"com.example/user": "bob"},
        {"x.y/sub": "root"},
        {"com.example/tenant": "evil-corp"},
        {"com.example/client_id": "other-app"},
        {"com.example/role": "admin"},
        {"com.example/scopes": ["read", "delete"]},
        {"com.example/scopes": 42},
        {"com.example/is_admin": True},
    ])
    def test_conflicting_or_expanding_claims_rejected(self, claim: dict[str, Any]) -> None:
        with pytest.raises(MetaTrustError):
            reconcile_meta({**_META, **claim}, ALICE)

    def test_tenant_claim_rejected_when_principal_has_no_tenant(self) -> None:
        with pytest.raises(MetaTrustError):
            reconcile_meta({"com.example/tenant": "acme"},
                           AuthenticatedPrincipal(subject="alice"))

    def test_error_never_echoes_claimed_values(self) -> None:
        seen: list[tuple[str, ...]] = []
        with pytest.raises(MetaTrustError) as ei:
            reconcile_meta({"com.example/user": "<script>bob</script>"}, ALICE,
                           on_mismatch=seen.append)
        assert "bob" not in str(ei.value) and seen == [("com.example/user",)]


def test_traceparent_parsing() -> None:
    tp = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"
    assert parse_traceparent(tp) == ("0af7651916cd43dd8448eb211c80319c",
                                     "00f067aa0ba902b7", "01")
    for bad in ("", "01-" + tp[3:], "00-" + "0" * 32 + "-00f067aa0ba902b7-01", 7):
        assert parse_traceparent(bad) is None


def test_baggage_allowlisted_bounded_and_no_identity() -> None:
    raw = "env=prod,user_id=alice,tenant=acme,feature=x;prop=1,junk key=1," + \
          ",".join(f"k{i}=v" for i in range(200))
    out = sanitize_baggage(raw, allowed_keys={"env", "feature", "user_id", "tenant"})
    assert out == "env=prod,feature=x"
    big = sanitize_baggage("env=" + "a" * 5000, allowed_keys={"env"}, max_bytes=100)
    assert big is None or len(big) <= 100


def test_server_cannot_overwrite_client_trace_identity() -> None:
    client = {"traceparent": "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"}
    child = {"traceparent": "00-0af7651916cd43dd8448eb211c80319c-1111111111111111-01"}
    hijack = {"traceparent": "00-ffffffffffffffffffffffffffffffff-1111111111111111-01"}
    assert preserve_client_trace(client, child) == (child, False)
    assert preserve_client_trace(client, hijack) == (client, True)
    assert preserve_client_trace(None, child) == (child, False)


class _Store:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    def add_if_absent(self, jti: str, expires_at: float) -> bool:
        if jti in self.seen:
            return False
        self.seen.add(jti)
        return True


class TestStateRegressions:
    def test_regression_non_ascii_principal_roundtrip(self) -> None:
        s = _sealer()
        tok = s.seal({"x": 1}, principal="jürgen", tenant="tënant", request_id=RID)
        with pytest.raises(StateVerificationError):
            s.open(tok, principal="josé", tenant="tënant", request_id=RID)
        assert s.open(tok, principal="jürgen", tenant="tënant", request_id=RID) == {"x": 1}
        reg = HandleRegistry()
        h = reg.mint(principal="jürgen", tenant="acmé", kind="task", ttl_seconds=60)
        assert reg.resolve(h, principal="jürgen", tenant="acmé")
        with pytest.raises(HandleError):
            reg.resolve(h, principal="josé", tenant="acmé")

    def test_regression_revoke_principal_callback_failure_continues(self) -> None:
        called: list[str] = []

        def cb(r: Any) -> None:
            called.append(r.handle)
            if len(called) == 1:
                raise RuntimeError("boom")

        reg = HandleRegistry(on_revoke=cb)
        hs = {reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=60)
              for _ in range(3)}
        with pytest.raises(RuntimeError):
            reg.revoke_principal("a")
        assert set(called) == hs and reg.list_for_principal("a") == []

    def test_regression_seal_rejects_oversized_state(self) -> None:
        s = _sealer()
        with pytest.raises(ValueError):
            s.seal({"blob": "x" * 70_000}, tenant="t", principal="a", request_id=RID)
        tok = s.seal({"blob": "x" * 40_000}, tenant="t", principal="a", request_id=RID)
        assert s.open(tok, tenant="t", principal="a", request_id=RID)["blob"] == "x" * 40_000

    def test_regression_fingerprint_no_str_coercion_collision(self) -> None:
        class Obj:
            def __str__(self) -> str:
                return "x"

        assert request_fingerprint("m", {"a": 5}) != request_fingerprint("m", {"a": "5"})
        with pytest.raises(TypeError):
            request_fingerprint("m", {"a": Obj()})
        with pytest.raises(ValueError):
            request_fingerprint("m", {"a": float("nan")})

    def test_regression_seal_counter_limit_forces_rotation(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        import mcp_armor.explicit_state as st
        monkeypatch.setattr(st, "_MAX_SEALS_PER_KEY", 2)
        s = _sealer()
        s.seal({}, tenant="t", principal="a", request_id=RID)
        s.seal({}, tenant="t", principal="a", request_id=RID)
        with pytest.raises(RuntimeError):
            s.seal({}, tenant="t", principal="a", request_id=RID)

    def test_exploit_requeststate_replay_default_rejected(self) -> None:
        s = RequestStateSealer({"k1": _K1}, active_kid="k1", audience="aud")
        tok = s.seal({}, tenant="t", principal="a", request_id=RID)
        s.open(tok, tenant="t", principal="a", request_id=RID)
        with pytest.raises(StateVerificationError):
            s.open(tok, tenant="t", principal="a", request_id=RID)

    def test_regression_single_use_shared_store_atomic(self) -> None:
        store = _Store()
        keys = {"k1": _K1}
        a = RequestStateSealer(keys, active_kid="k1", audience="aud", spent_store=store)
        b = RequestStateSealer(keys, active_kid="k1", audience="aud", spent_store=store)
        tok = a.seal({}, tenant="t", principal="p", request_id=RID)
        a.open(tok, tenant="t", principal="p", request_id=RID)
        with pytest.raises(StateVerificationError):
            b.open(tok, tenant="t", principal="p", request_id=RID)

    def test_regression_single_use_store_failure_fails_closed(self) -> None:
        class Broken:
            def add_if_absent(self, jti: str, expires_at: float) -> bool:
                raise ConnectionError

        s = RequestStateSealer({"k1": _K1}, active_kid="k1", audience="aud",
                               spent_store=Broken())
        tok = s.seal({}, tenant="t", principal="p", request_id=RID)
        with pytest.raises(StateVerificationError):
            s.open(tok, tenant="t", principal="p", request_id=RID)

    def test_exploit_requeststate_cross_tenant_rejected(self) -> None:
        keys = {"k1": _K1}
        x = RequestStateSealer(keys, active_kid="k1", audience="https://x/mcp")
        y = RequestStateSealer(keys, active_kid="k1", audience="https://y/mcp")
        tok = x.seal({}, principal="p", tenant="A", request_id=RID)
        with pytest.raises(StateVerificationError):
            x.open(tok, principal="p", tenant="B", request_id=RID)
        with pytest.raises(StateVerificationError):
            y.open(tok, principal="p", tenant="A", request_id=RID)
        assert x.open(tok, principal="p", tenant="A", request_id=RID) == {}

    def test_regression_per_principal_handle_cap(self) -> None:
        reg = HandleRegistry(max_handles_per_principal=2)
        for _ in range(2):
            reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=60)
        with pytest.raises(RuntimeError):
            reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=60)
        assert reg.mint(principal="b", tenant="t", kind="task", ttl_seconds=60)

    def test_regression_expired_handles_free_quota(self) -> None:
        clock = _Clock()
        reg = HandleRegistry(max_handles_per_principal=1, clock=clock)
        reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=5)
        clock.t += 6
        assert reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=5)

    def test_exploit_cross_tenant_revoke_rejected(self) -> None:
        cancelled: list[str] = []
        reg = HandleRegistry(on_revoke=lambda r: cancelled.append(r.handle))
        h = reg.mint(principal="alice", tenant="acme", kind="task", ttl_seconds=60)
        with pytest.raises(HandleError):
            reg.revoke(h, principal="mallory", tenant="evil")
        assert cancelled == [] and reg.resolve(h, principal="alice", tenant="acme")
        assert reg.revoke(h, principal="alice", tenant="acme") and cancelled == [h]


_SCHEMAS = {"sql": {"type": "object", "properties": {
    "region": {"type": "string", "x-mcp-header": "Region"},
    "limit": {"type": "integer", "x-mcp-header": "Limit"}}}}


def _sql(args: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    h, b = _request("tools/call", {"name": "sql", "arguments": args})
    from mcp_armor.mcp_protocol import x_mcp_param_headers
    h.update(x_mcp_param_headers(_SCHEMAS["sql"], args))
    return h, b


def _code(headers: Any, body: Any, **kw: Any) -> int:
    with pytest.raises(RequestMetadataError) as ei:
        validate_request_metadata(headers, body, **kw)
    return ei.value.code


class TestEnvelopeRegressions:
    def test_regression_error_code_selection_matrix(self) -> None:
        assert _code({"MCP-Protocol-Version": "2025-03-26"},
                     {"method": "initialize", "params": {}}) == -32602   # legacy fallback
        assert _code({"MCP-Protocol-Version": "1900-01-01"},
                     {"method": "initialize", "params": {}}) == -32022
        assert _code({}, {"method": "notifications/x"}) == -32602
        assert _code({}, {"method": "tools/list", "params": {"_meta": {}}}) == -32602
        assert _code({"MCP-Protocol-Version": MODERN_PROTOCOL_VERSION},
                     {"method": "tools/list", "params": {"_meta": {}}}) == -32020
        h, b = _request("tools/list", {})
        del h["Mcp-Method"]
        assert _code(h, b) == -32020

    def test_exploit_nonstring_name_with_header_rejected(self) -> None:
        h, b = _request("tools/call", {"name": ["t"], "arguments": {}})
        h["Mcp-Name"] = "public"
        assert _code(h, b) == -32602
        h, b = _request("tools/call", {"arguments": {}})
        assert _code(h, b) == -32602
        h, b = _request("tools/list", {})
        h["Mcp-Name"] = "x"
        assert _code(h, b) == -32020

    def test_exploit_param_header_without_body_value_rejected(self) -> None:
        for args in ({}, {"region": None}, {"limit": 2**60}):
            h, b = _sql(args)
            h["Mcp-Param-Region" if "limit" not in args else "Mcp-Param-Limit"] = "eu"
            assert _code(h, b, tool_schemas=_SCHEMAS) == -32020

    def test_exploit_string_param_numeric_equivalence_rejected(self) -> None:
        for body_val, header in (("10", "1_0.0"), ("10", "1e1"), ("10", "10.0"),
                                 ("10", " 10"), ("Infinity", "inf")):
            h, b = _sql({"region": body_val})
            h["Mcp-Param-Region"] = header
            assert _code(h, b, tool_schemas=_SCHEMAS) == -32020
        for header in ("5.0", "1_0", "05"):
            h, b = _sql({"limit": 5})
            h["Mcp-Param-Limit"] = header
            assert _code(h, b, tool_schemas=_SCHEMAS) == -32020
        h, b = _sql({"limit": 5, "region": "10"})
        assert validate_request_metadata(h, b, tool_schemas=_SCHEMAS)

    def test_exploit_noncanonical_base64_mcp_name_rejected(self) -> None:
        h, b = _request("tools/call", {"name": "t", "arguments": {}})
        h["Mcp-Name"] = "=?base64?dA==?="
        assert _code(h, b) == -32020
        h, b = _sql({"region": "eu"})
        h["Mcp-Param-Region"] = "=?base64?ZXU=?="
        assert _code(h, b, tool_schemas=_SCHEMAS) == -32020

    def test_exploit_duplicate_mcp_method_header_rejected(self) -> None:
        h, b = _request("tools/list", {})
        for dup in ("tools/call", "tools/list"):
            pairs = [*h.items(), ("mcp-method", dup)]
            assert _code(pairs, b) == -32020
        joined = dict(h, **{"Mcp-Method": "tools/list, tools/call"})
        assert _code(joined, b) == -32020
        assert validate_request_metadata(list(h.items()), b)

    @pytest.mark.parametrize("claim", [
        {"com.acme.tenant_id": "evil"},
        {"x/user-id": "bob"},
        {"x/enduser.id": "bob"},
        {"x/impersonate": "bob"},
        {"X-Tenant-ID": "evil"},
        {"client.id": "other"},
        {"is-admin": True},
        {"ｔｅｎａｎｔ": "evil"},
        {"acme/identity": {"user": "bob"}},
        {"auth": {"tenant": "other"}},
        {"a": {"b": {"c": {"d": {"e": 1}}}}},
    ])
    def test_exploit_meta_identity_smuggling_variants(self, claim: dict[str, Any]) -> None:
        with pytest.raises(MetaTrustError):
            reconcile_meta(claim, ALICE)

    def test_regression_meta_allowlist_mode(self) -> None:
        reconcile_meta({**_META, "com.acme/feature": 1,
                        "traceparent": "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"},
                       ALICE,
                       allowed_keys={"com.acme/feature"})
        with pytest.raises(MetaTrustError):
            reconcile_meta({"com.acme/other": 1}, ALICE, allowed_keys={"com.acme/feature"})


def test_exploit_traceparent_returned_canonical() -> None:
    trace = "0af7651916cd43dd8448eb211c80319c"
    client = {"traceparent": f"00-{trace}-00f067aa0ba902b7-01"}
    server = {"traceparent": f"  00-{trace}-1111111111111111-01\r\n"}
    out, _ = preserve_client_trace(client, server)
    assert out["traceparent"] == f"00-{trace}-1111111111111111-01"
    out, _ = preserve_client_trace({"traceparent": " " + client["traceparent"] + "\n"}, None)
    assert out["traceparent"] == client["traceparent"]


def test_exploit_baggage_enduser_id_dropped_and_oversize_rejected() -> None:
    allowed = {"enduser.id", "tenant-id", "session.id", "env", "api_key"}
    assert sanitize_baggage("enduser.id=bob,tenant-id=acme,session.id=s,api_key=k,env=p",
                            allowed) == "env=p"
    assert sanitize_baggage("env=p," + "x" * 9000, {"env"}) is None
    assert sanitize_baggage("env=" + "a" * 2000 + ",env2=b", {"env", "env2"}) == "env2=b"


def test_exploit_requeststate_requires_audience_and_tenant() -> None:
    with pytest.raises(TypeError):
        RequestStateSealer({"k1": _K1}, active_kid="k1")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        RequestStateSealer({"k1": _K1}, active_kid="k1", audience="")
    s = _sealer()
    with pytest.raises(TypeError):
        s.seal({}, principal="p", request_id=RID)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        s.seal({}, principal="p", request_id=RID, tenant="")


def test_exploit_handle_quota_cross_tenant_isolated() -> None:
    reg = HandleRegistry(max_handles_per_principal=3)
    for _ in range(3):
        reg.mint(principal="alice", tenant="EVIL", kind="task", ttl_seconds=60)
    assert reg.mint(principal="alice", tenant="A", kind="task", ttl_seconds=60)


def test_regression_unannotated_param_header_rejected() -> None:
    schemas = {**_SCHEMAS, "pay": {"type": "object", "properties": {
        "amount": {"type": "number", "x-mcp-header": "Amount"},
        "bad": {"type": "string", "x-mcp-header": "bad name"}}}}
    h, b = _sql({"region": "eu"})
    h["Mcp-Param-Secret"] = "x"
    assert _code(h, b, tool_schemas=schemas) == -32020
    h, b = _request("tools/call", {"name": "pay", "arguments": {"amount": 999}})
    h["Mcp-Param-Amount"] = "999"
    assert _code(h, b, tool_schemas=schemas) == -32020
    for method in ("tools/list", "resources/list"):
        h, b = _request(method, {})
        h["Mcp-Param-Region"] = "eu"
        assert _code(h, b) == -32020
        assert _code(h, b, tool_schemas=schemas) == -32020


@pytest.mark.parametrize("claim", [
    {"x": [{"user": "bob"}]},
    {"acme/ctx": [{"tenant_id": "B", "role": "admin"}]},
    {"tenant:id": "evil"},
    {"acme:tenant": "evil"},
    {"x/tenant/id": "evil"},
    {"user@id": "bob"},
    {"acme/organization_id": "B"},
    {"acme/user_email": "bob@x"},
    {"acme/as_user": "bob"},
    {"acme/delegate": "bob"},
    {"acme/actingAs": "bob"},
    {"acme/delegatedUser": "bob"},
    {"traceparent": {"tenant_id": "B"}},
    {"traceparent": "not-a-traceparent"},
    {"tracestate": ["x"]},
    {META_CLIENT_INFO: {"name": "c", "tenant_id": "B"}},
    {"baggage": "enduser.id=bob,env=p"},
    {"baggage": "tenant.id=B"},
])
def test_exploit_meta_identity_smuggling_round2(claim: dict[str, Any]) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta(claim, ALICE)
    with pytest.raises(MetaTrustError):
        reconcile_meta(claim, ALICE, allowed_keys={"x", "acme/ctx"})


def test_regression_meta_benign_keys_still_pass() -> None:
    reconcile_meta({**_META, "org.example/feature": 1, "x/tenant.id": "acme",
                    "acme/ctx": [{"tenant_id": "acme"}], "baggage": "env=prod",
                    "traceparent": "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01",
                    "tracestate": "k=v"}, ALICE)


def test_regression_meta_list_path_reported() -> None:
    seen: list[tuple[str, ...]] = []
    with pytest.raises(MetaTrustError):
        reconcile_meta({"acme/ctx": [{"tenant_id": "B"}]}, ALICE, on_mismatch=seen.append)
    assert seen == [("acme/ctx>0>tenant_id",)]


def test_regression_allowlisted_vendor_key_with_identity_word_passes() -> None:
    reconcile_meta({"x/userAgent": "c"}, ALICE, allowed_keys={"x/userAgent"})
    with pytest.raises(MetaTrustError):
        reconcile_meta({"x/userAgent": "c"}, ALICE)
    with pytest.raises(MetaTrustError):
        reconcile_meta({"x/user": "bob"}, ALICE, allowed_keys={"x/user"})
    with pytest.raises(MetaTrustError):
        reconcile_meta({"x/userAgent": {"tenant": "B"}}, ALICE, allowed_keys={"x/userAgent"})


@pytest.mark.parametrize("meta", [
    {"baggage": "%75ser_id=victim"},
    {"baggage": "tenant%5Fid=t2"},
    {"baggage": "k=v;user=bob"},
    {"baggage": "k=v;%75ser"},
    {"tracestate": "user=bob"},
    {"tracestate": "vendor=x,tenant_id=t2"},
])
def test_exploit_percent_encoded_and_property_baggage_identity_rejected(
        meta: dict[str, Any]) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta(meta, ALICE)


def test_regression_sanitize_baggage_shares_identity_predicate() -> None:
    for key in ("workspace_id", "project_id", "team_id", "customer", "realm", "owner",
                "actor", "delegatedUser"):
        assert sanitize_baggage(f"{key}=t2", [key]) is None
    assert sanitize_baggage("env=p", ["env"]) == "env=p"


def test_exploit_one_principal_cannot_exhaust_spent_cache_for_others(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_armor.explicit_state as st
    monkeypatch.setattr(st, "_MAX_SPENT_PER_OWNER", 3)
    s = _sealer()
    for _ in range(3):
        s.open(s.seal({}, principal="A", tenant="t", request_id=RID),
               principal="A", tenant="t", request_id=RID)
    with pytest.raises(StateVerificationError):
        s.open(s.seal({}, principal="A", tenant="t", request_id=RID),
               principal="A", tenant="t", request_id=RID)
    assert s.open(s.seal({}, principal="B", tenant="t", request_id=RID),
                  principal="B", tenant="t", request_id=RID) == {}


def test_regression_spent_cache_purges_expired_entries() -> None:
    import mcp_armor.explicit_state as st
    clock = _Clock()
    s = _sealer(clock=clock, default_ttl_seconds=10)
    for _ in range(5):
        s.open(s.seal({}, principal="A", tenant="t", request_id=RID),
               principal="A", tenant="t", request_id=RID)
    clock.t += 11
    s.open(s.seal({}, principal="A", tenant="t", request_id=RID),
           principal="A", tenant="t", request_id=RID)
    assert len(s._spent) == 1 and s._spent_per_owner == {("A", "t"): 1}
    assert st._MAX_SPENT_PER_OWNER > 0


@pytest.mark.parametrize("key", ["tenant.slug", "acme/tenant.slug", "user.handle",
                                 "acme/tenant/slug", "a/b/c"])
def test_exploit_identity_word_in_non_final_key_segment_rejected(key: str) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta({key: "t2"}, ALICE)
    reconcile_meta({"io.example/feature": 1, "io.example/feature.flag": True}, ALICE)


@pytest.mark.parametrize("key", ["x/us​er.handle", "x/ten­ant.slug",
                                 "x/ro⁠le.name"])
def test_regression_identity_key_zero_width_and_soft_hyphen_split(key: str) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta({key: "t2"}, ALICE)
    bkey = key.split("/", 1)[1]
    assert sanitize_baggage(f"{bkey}=1", [bkey]) is None
    reconcile_meta({"io.example/feature.flag": True}, ALICE)


@pytest.mark.parametrize("key", ["acme/userrole", "acme/TENANTNAME", "acme/issuperuser",
                                 "acme/adminmode", "acme/actasuser"])
def test_exploit_unsegmented_compound_identity_key_rejected(key: str) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta({key: "admin"}, ALICE)


def test_regression_compound_identity_baggage_and_allowlist() -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta({"baggage": "userrole=admin"}, ALICE)
    reconcile_meta({"acme/useragent": "c"}, ALICE, allowed_keys={"acme/useragent"})
    reconcile_meta({"io.example/feature.flag": True, "acme/ctx": {"mode": 1}}, ALICE)


def test_exploit_many_principals_cannot_exhaust_spent_cache_or_handle_registry(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_armor.explicit_state as st
    monkeypatch.setattr(st, "_MAX_SPENT_ENTRIES", 4)
    monkeypatch.setattr(st, "_MAX_SPENT_PER_OWNER", 100)
    monkeypatch.setattr(st, "_OWNER_FLOOR", 2)
    s = _sealer()

    def redeem(p: str) -> None:
        s.open(s.seal({}, principal=p, tenant="t", request_id=RID),
               principal=p, tenant="t", request_id=RID)

    for p in ("A", "A", "B", "B"):
        redeem(p)
    with pytest.raises(StateVerificationError):
        redeem("A")                       # at floor, global full
    redeem("victim")                      # below floor: admitted
    reg = HandleRegistry(max_handles=4, max_handles_per_principal=100,
                         max_handles_per_tenant=100)
    monkeypatch.setattr(st, "_OWNER_FLOOR", 2)
    for p in ("A", "A", "B", "B"):
        reg.mint(principal=p, tenant="t", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        reg.mint(principal="A", tenant="t", kind="task", ttl_seconds=60)
    assert reg.mint(principal="victim", tenant="t", kind="task", ttl_seconds=60)


@pytest.mark.parametrize("key", ["x/us️er.handle", "x/ten͏ant.slug",
                                 "x/róle.name"])
def test_regression_identity_key_combining_mark_and_variation_selector_split(key: str) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta({key: "t2"}, ALICE)
    bkey = key.split("/", 1)[1]
    assert sanitize_baggage(f"{bkey}=1", [bkey]) is None
    reconcile_meta({"io.example/feature.flag": True}, ALICE)


@pytest.mark.parametrize("key", ["x/team.name", "x/caller.id", "x/groupName",
                                 "x/projectName", "x/actas", "x/onBehalfOf.x"])
def test_regression_identity_names_without_token_counterpart_rejected(key: str) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta({key: "t2"}, ALICE)


def test_regression_identity_names_and_tokens_stay_in_sync() -> None:
    from mcp_armor.meta_identity import IDENTITY_NAMES, TOKEN_EXEMPT_WORDS, has_identity_word
    assert [w for w in IDENTITY_NAMES - TOKEN_EXEMPT_WORDS
            if not has_identity_word(w + ".x")] == []
    # pinned exemptions: common non-identity compounds stay allowed
    reconcile_meta({"x/rootDir": "/", "x/clientVersion": "1", "x/actions": []}, ALICE)


def test_regression_owner_floor_hard_ceiling_and_boundary(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_armor.explicit_state as st
    monkeypatch.setattr(st, "_MAX_SPENT_ENTRIES", 2)
    monkeypatch.setattr(st, "_MAX_SPENT_PER_OWNER", 100)
    monkeypatch.setattr(st, "_OWNER_FLOOR", 2)
    clock = _Clock()
    s = _sealer(clock=clock, default_ttl_seconds=10)

    def redeem(p: str) -> None:
        s.open(s.seal({}, principal=p, tenant="t", request_id=RID),
               principal=p, tenant="t", request_id=RID)

    redeem("A")
    redeem("A")                   # global full (2)
    redeem("B")                   # B=0 < floor: admitted
    redeem("B")                   # B=1 < floor: admitted (total 4 = 2x ceiling)
    with pytest.raises(StateVerificationError):
        redeem("C")               # below floor but at the 2x hard ceiling
    clock.t += 11
    redeem("C")
    assert s._spent_per_owner == {("C", "t"): 1}

    reg = HandleRegistry(max_handles=2, max_handles_per_principal=100,
                         max_handles_per_tenant=100)
    for p in ("A", "A", "B", "B"):
        reg.mint(principal=p, tenant="t", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        reg.mint(principal="C", tenant="t", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        reg.mint(principal="B", tenant="t", kind="task", ttl_seconds=60)  # B at floor


def test_exploit_single_tenant_sybils_cannot_exhaust_other_tenants(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_armor.explicit_state as st
    monkeypatch.setattr(st, "_OWNER_FLOOR", 0)   # isolate the tenant partition
    reg = HandleRegistry(max_handles=100, max_handles_per_principal=1000)
    minted = 0
    for i in range(100):
        try:
            reg.mint(principal=f"sybil{i}", tenant="evil", kind="task", ttl_seconds=60)
            minted += 1
        except RuntimeError:
            pass
    assert minted == 25                          # tenant share = max // 4
    assert reg.mint(principal="bob", tenant="good", kind="task", ttl_seconds=60)

    monkeypatch.setattr(st, "_MAX_SPENT_PER_TENANT", 3)
    s = _sealer()

    def redeem(p: str, t: str) -> None:
        s.open(s.seal({}, principal=p, tenant=t, request_id=RID),
               principal=p, tenant=t, request_id=RID)

    for i in range(3):
        redeem(f"sybil{i}", "evil")
    with pytest.raises(StateVerificationError):
        redeem("sybil9", "evil")
    redeem("bob", "good")


def test_regression_tenant_counters_released_on_expiry_revoke_and_purge(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_armor.explicit_state as st
    monkeypatch.setattr(st, "_MAX_SPENT_PER_TENANT", 2)
    monkeypatch.setattr(st, "_OWNER_FLOOR", 0)   # isolate the tenant cap itself
    clock = _Clock()
    s = _sealer(clock=clock, default_ttl_seconds=10)

    def redeem(p: str) -> None:
        s.open(s.seal({}, principal=p, tenant="T", request_id=RID),
               principal=p, tenant="T", request_id=RID)

    redeem("a")
    redeem("b")
    with pytest.raises(StateVerificationError):
        redeem("c")
    clock.t += 11
    redeem("c")                                   # expiry released the tenant cap
    assert s._spent_per_tenant == {"T": 1}

    clock2 = _Clock()
    reg = HandleRegistry(max_handles_per_tenant=2, clock=clock2)
    h1 = reg.mint(principal="a", tenant="T", kind="task", ttl_seconds=60)
    h2 = reg.mint(principal="b", tenant="T", kind="task", ttl_seconds=60)
    other = reg.mint(principal="a", tenant="U", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        reg.mint(principal="c", tenant="T", kind="task", ttl_seconds=60)
    reg.revoke(h1, principal="a", tenant="T")
    h3 = reg.mint(principal="c", tenant="T", kind="task", ttl_seconds=5)  # cap released
    reg.admin_revoke(h2)
    reg.revoke_principal("c", tenant="T")
    assert reg._tenant_counts == {"U": 1} and reg._counts == {("a", "U"): 1}
    with pytest.raises(HandleError):
        reg.resolve(h3, principal="c", tenant="T")
    reg.mint(principal="d", tenant="T", kind="task", ttl_seconds=5)
    clock2.t += 6
    assert reg.list_for_principal("d") == []      # expiry purge
    assert reg._tenant_counts == {"U": 1}
    assert reg.resolve(other, principal="a", tenant="U")


def test_regression_identity_affix_false_positives_allowed() -> None:
    benign = ["x/scalingFactor", "x/refactor", "x/telescope", "x/steam", "x/teamwork",
              "x/groupingMode"]
    reconcile_meta(dict.fromkeys(benign, 1), ALICE)
    for k in benign:
        b = k.split("/", 1)[1]
        assert sanitize_baggage(f"{b}=1", [b]) == f"{b}=1"
    for k in ("x/userrole", "x/TENANTNAME", "x/issuperuser", "x/userId", "x/adminmode",
              "x/actasuser"):
        with pytest.raises(MetaTrustError):
            reconcile_meta({k: "admin"}, ALICE)


@pytest.mark.parametrize("meta", [
    {"tenant/id": "victim"}, {"user/id": "victim"}, {"org/id": "victim"},
    {"tenant/name": "victim"}, {"tenant/slug": "victim"}, {"acme.tenant/id": "victim"},
    {"com.acme.user/id": "victim"},
    {"acme/ctx": {"tenant/id": "victim"}},
    {META_CLIENT_INFO: {"name": "x", "tenant/id": "v"}},
    {"tracestate": "tenant/id=x"},
])
def test_exploit_identity_word_in_meta_prefix_or_nested_slash_key_rejected(
        meta: dict[str, Any]) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta(meta, ALICE)


def test_regression_reverse_dns_prefix_still_allowed() -> None:
    reconcile_meta({"org.example/feature": 1, "com.example.tools/flag": True,
                    "io.example/feature.flag": True}, ALICE)


def test_exploit_intra_tenant_sybils_cannot_lock_out_tenant_peers(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_armor.explicit_state as st
    monkeypatch.setattr(st, "_MAX_SPENT_PER_TENANT", 4)
    monkeypatch.setattr(st, "_OWNER_FLOOR", 2)
    s = _sealer()

    def redeem(p: str) -> None:
        s.open(s.seal({}, principal=p, tenant="default", request_id=RID),
               principal=p, tenant="default", request_id=RID)

    for p in ("s1", "s1", "s2", "s2"):
        redeem(p)
    with pytest.raises(StateVerificationError):
        redeem("s1")                  # Sybil at floor, tenant full
    redeem("alice")                   # peer below floor still admitted
    reg = HandleRegistry(max_handles_per_tenant=4)
    for p in ("s1", "s1", "s2", "s2"):
        reg.mint(principal=p, tenant="default", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        for _ in range(st._OWNER_FLOOR + 1):
            reg.mint(principal="s1", tenant="default", kind="task", ttl_seconds=60)
    assert reg.mint(principal="alice", tenant="default", kind="task", ttl_seconds=60)


@pytest.mark.parametrize("claim", [{"acme/tid": "victim-tenant"}, {"acme/oid": "victim"},
                                   {"acme/upn": "v@x"}, {"acme/wids": ["r"]},
                                   {"acme/iss": "https://x"}, {"acme/aud": "y"},
                                   {"acme/login": "victim"}, {"acme/unique_name": "v"},
                                   {"acme/appid": "v"}, {"acme/cid": "v"},
                                   {"acme/resource_access": {}}, {"acme/given_name": "v"}])
def test_exploit_entra_oidc_claim_names_rejected(claim: dict[str, Any]) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta(claim, ALICE)


def test_exploit_entra_oidc_claim_names_rejected_v1() -> None:
    assert sanitize_baggage("unique_name=v", ["unique_name"]) is None
    assert sanitize_baggage("given_name=v", ["given_name"]) is None


def test_regression_owner_floor_tenant_2x_ceiling_sealer_and_registry(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_armor.explicit_state as st
    monkeypatch.setattr(st, "_MAX_SPENT_PER_TENANT", 2)
    monkeypatch.setattr(st, "_OWNER_FLOOR", 2)
    s = _sealer()

    def redeem(p: str) -> None:
        s.open(s.seal({}, principal=p, tenant="T", request_id=RID),
               principal=p, tenant="T", request_id=RID)

    redeem("a")
    redeem("a")                       # tenant cap reached
    redeem("b")                       # b below floor: admitted
    redeem("c")                       # c below floor: admitted (tenant = 4 = 2x)
    with pytest.raises(StateVerificationError):
        redeem("d")                   # below floor, but tenant 2x ceiling reached
    assert s._spent_per_tenant == {"T": 4}

    reg = HandleRegistry(max_handles_per_tenant=2)
    for p in ("a", "a"):
        reg.mint(principal=p, tenant="T", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        reg.mint(principal="a", tenant="T", kind="task", ttl_seconds=60)   # a at floor
    reg.mint(principal="b", tenant="T", kind="task", ttl_seconds=60)
    reg.mint(principal="c", tenant="T", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        reg.mint(principal="d", tenant="T", kind="task", ttl_seconds=60)   # 2x ceiling
    assert reg._tenant_counts == {"T": 4}


ADMIN = AuthenticatedPrincipal(subject="alice", tenant="t1", scopes=frozenset({"admin"}))


def test_exploit_admin_key_mapping_value_cannot_smuggle_nested_claims() -> None:
    meta = {"acme/admin": {"tenant": "t2", "user": "bob", "roles": ["root"]}}
    with pytest.raises(MetaTrustError):
        reconcile_meta(meta, ADMIN)
    with pytest.raises(MetaTrustError):
        reconcile_meta(meta, ADMIN, allowed_keys=["acme/admin"])
    reconcile_meta({"acme/admin": True}, ADMIN)            # scalar restating scope is fine



def test_regression_weak_sealing_keys_rejected() -> None:
    import os

    for weak in (b"\x00" * 32, b"\x01" * 32, bytes(range(8)) * 4,
                 b"correct horse battery staple!!!!", b"k" * 32):
        with pytest.raises(ValueError, match="non-random"):
            RequestStateSealer({"k1": weak}, active_kid="k1", audience="aud")
    with pytest.raises(ValueError, match="non-random"):   # any configured key, not just active
        RequestStateSealer({"k1": os.urandom(32), "old": b"\x02" * 32},
                           active_kid="k1", audience="aud")
    for _ in range(200):
        RequestStateSealer({"k1": os.urandom(32)}, active_kid="k1", audience="aud")


# ===========================================================================
# OCSF agentic API Activity (LO-01 / LO-04) — parity with cosai-mcp
# ===========================================================================


def test_ocsf_activity_has_agentic_fields_and_hashes_params() -> None:
    import json

    from mcp_armor.ocsf import build_mcp_api_activity

    ev = build_mcp_api_activity(
        server="https://mcp.example/mcp", mcp_method="tools/call", mcp_name="echo",
        decision="deny", principal="alice", tenant="acme",
        params={"password": "hunter2"}, params_key=_K1, correlation_id="c-1",
        delegation_path=["user:alice", "agent:planner"], attestation_state="verified",
        trace_id="0af7651916cd43dd8448eb211c80319c", reason="meta_mismatch",
    ).to_dict()
    agentic = ev["unmapped"]["cosai_agentic"]
    assert ev["class_uid"] == 6003 and ev["metadata"]["product"]["name"] == "mcp-armor"
    assert {"delegation_path", "attestation_state", "correlation_id", "mcp_method",
            "mcp_name"} <= agentic.keys()
    assert "hunter2" not in json.dumps(ev) and len(agentic["params_hmac_sha256"]) == 64
    with pytest.raises(ValueError):
        build_mcp_api_activity(server="s", mcp_method="m", decision="maybe")


def test_regression_ocsf_no_digest_without_key_and_short_key_rejected() -> None:
    from mcp_armor.ocsf import build_mcp_api_activity

    ev = build_mcp_api_activity(server="s", mcp_method="tools/call", decision="allow",
                                params={"id": 7}).to_dict()
    assert ev["unmapped"]["cosai_agentic"]["params_hmac_sha256"] is None
    with pytest.raises(ValueError):
        build_mcp_api_activity(server="s", mcp_method="m", decision="allow",
                               params={"a": 1}, params_key=b"short")
    bad = build_mcp_api_activity(server="s", mcp_method="m", decision="allow",
                                 params={"a": object()}, params_key=_K1).to_dict()
    assert bad["unmapped"]["cosai_agentic"]["params_unserializable"] is True


def test_regression_ocsf_matches_cosai_mcp_shape() -> None:
    cosai = pytest.importorskip("cosai_mcp.telemetry.ocsf")
    from mcp_armor.ocsf import build_mcp_api_activity

    kw: dict[str, Any] = {"server": "s", "mcp_method": "tools/call", "decision": "deny",
                          "principal": "p", "params": {"x": 1}, "params_key": _K1,
                          "timestamp_ms": 1}
    a = build_mcp_api_activity(**kw).to_dict()
    b = cosai.build_mcp_api_activity(**kw).to_dict()
    a["metadata"]["product"] = b["metadata"]["product"] = None
    assert a == b



def _golden_ocsf_event(product: str) -> dict[str, Any]:
    """Golden OCSF 6003 event shared verbatim by cosai-mcp and mcp-armor tests
    (only metadata.product differs) — keeps the two builders identical."""
    import hmac

    digest = hmac.new(_K1, b'{"q":1}', hashlib.sha256).hexdigest()
    return {
        "activity_id": 99, "activity_name": "Other",
        "actor": {"tenant_uid": "acme", "user": {"uid": "alice"}},
        "api": {"operation": "tools/call",
                "service": {"name": "MCP", "uid": "https://mcp.example/mcp"}},
        "category_name": "Application Activity", "category_uid": 6,
        "class_name": "API Activity", "class_uid": 6003,
        "metadata": {"correlation_uid": "c-1",
                     "product": {"name": product, "vendor_name": "CoSAI"},
                     "version": "2.0.0"},
        "severity_id": 3, "status_id": 2, "time": 1, "type_uid": 600399,
        "unmapped": {"cosai_agentic": {
            "attestation_state": "verified", "correlation_id": "c-1", "decision": "deny",
            "delegation_path": ["user:alice", "agent:planner"], "mcp_method": "tools/call",
            "mcp_name": "echo", "params_hmac_sha256": digest,
            "params_unserializable": False, "reason": "meta_mismatch",
            "trace_id": "0af7651916cd43dd8448eb211c80319c"}},
    }


def test_regression_ocsf_golden_shape_without_cosai() -> None:
    from mcp_armor.ocsf import build_mcp_api_activity as build

    ev = build(server="https://mcp.example/mcp", mcp_method="tools/call", mcp_name="echo",
               decision="deny", principal="alice", tenant="acme", params={"q": 1},
               params_key=_K1, correlation_id="c-1",
               delegation_path=["user:alice", "agent:planner"], attestation_state="verified",
               trace_id="0af7651916cd43dd8448eb211c80319c", reason="meta_mismatch",
               timestamp_ms=1).to_dict()
    assert ev == _golden_ocsf_event("mcp-armor")
