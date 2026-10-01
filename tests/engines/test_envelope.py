"""EnvelopeEngine — CoSAI v2.0 TN-04 / SD-02 parity, through the guard and the
ASGI adapter (opt-in via T7.enforce_request_envelope)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mcp_armor.adapters.fastapi import ArmorMiddleware
from mcp_armor.config import ConfigError, load_config
from mcp_armor.engines.envelope import EnvelopeEngine
from mcp_armor.engines.session import SessionEngine
from mcp_armor.exceptions import AuthorizationError, to_http_status, to_jsonrpc_error
from mcp_armor.guard import CoSAIGuard
from mcp_armor.mcp_protocol import (
    META_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
    request_metadata_headers,
)
from mcp_armor.request_envelope import MetaTrustError, RequestMetadataError
from tests.conftest import make_ctx, make_request

_META = {META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION}


def _ctx() -> Any:
    return make_ctx().with_user("alice", "acme").with_scopes(("read",))


def _modern(method: str, params: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    params = {**params, "_meta": {**_META, **params.get("_meta", {})}}
    return request_metadata_headers(method, params), params


# --- config / wiring ---------------------------------------------------------


def _write(tmp_path: Path, t7: str) -> Path:
    p = tmp_path / "cosai.yaml"
    p.write_text(f"version: 1\nthreats:\n  T7:\n{t7}\n  T12:\n    enabled: false\n")
    return p


def test_envelope_engine_opt_in_and_ordered_after_session(tmp_path: Path) -> None:
    off = CoSAIGuard.from_config(_write(tmp_path, "    enabled: true"))
    assert not any(isinstance(e, EnvelopeEngine) for e in off._engines)
    on = CoSAIGuard.from_config(_write(
        tmp_path,
        "    enforce_request_envelope: true\n    allowed_meta_keys: ['x/feature']"))
    from mcp_armor.engines.authz import AuthzEngine

    kinds = [type(e) for e in on._engines]
    # after T1/T7 and after T2 (no hidden-tool oracle)
    assert kinds.index(EnvelopeEngine) == kinds.index(AuthzEngine) + 1
    assert kinds.index(EnvelopeEngine) > kinds.index(SessionEngine)
    cfg = load_config(tmp_path / "cosai.yaml")
    assert cfg.t7 is not None and cfg.t7.allowed_meta_keys == ("x/feature",)


def test_unknown_t7_key_still_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, "    enforce_envelope: true"))


def test_regression_protect_t7_does_not_claim_envelope_enforcement() -> None:
    from mcp_armor.guard import _THREAT_ENGINE_TYPES

    assert _THREAT_ENGINE_TYPES["T7"] is SessionEngine


def test_regression_envelope_requires_t1_in_config(
        tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING", logger="mcp_armor.guard"):
        CoSAIGuard.from_config(_write(
            tmp_path, "    enforce_request_envelope: true\n  T1:\n    enabled: false"))
    assert any("T1 is disabled" in r.getMessage() for r in caplog.records)


# --- guard entry point ---------------------------------------------------------


async def test_meta_identity_claim_rejected_through_guard() -> None:
    guard = CoSAIGuard([EnvelopeEngine()])
    req = make_request("tools/call", {"name": "t", "arguments": {},
                                      "_meta": {"x/tenant_id": "evil"}})
    with pytest.raises(MetaTrustError) as ei:
        await guard._run_request(_ctx(), req)
    assert isinstance(ei.value, AuthorizationError)
    assert to_http_status(ei.value) == 403


async def test_meta_claim_not_suppressed_by_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARMOR_ALLOW_DRY_RUN", "1")
    guard = CoSAIGuard([EnvelopeEngine()], dry_run=True)
    req = make_request("tools/list", {"_meta": {"x/user": "bob"}})
    with pytest.raises(MetaTrustError):
        await guard._run_request(_ctx(), req)


async def test_legacy_request_without_signals_passes() -> None:
    guard = CoSAIGuard([EnvelopeEngine()])
    ctx = await guard._run_request(_ctx(), make_request("tools/call", {"name": "t"}))
    assert ctx.user_id == "alice"
    await guard._run_request(_ctx(), make_request("tools/list", {"_meta": {"x/user": "alice"}}))


async def test_modern_request_consistent_headers_pass_and_mismatch_rejected() -> None:
    guard = CoSAIGuard([EnvelopeEngine()])
    guard.register_tool_schemas([{"name": "echo", "inputSchema": {"type": "object"}}])
    headers, params = _modern("tools/call", {"name": "echo", "arguments": {}})
    await guard._run_request(_ctx(), make_request("tools/call", params, headers))
    with pytest.raises(RequestMetadataError) as ei:
        await guard._run_request(
            _ctx(), make_request("tools/call", params, {**headers, "Mcp-Name": "admin"}))
    assert ei.value.json_rpc_code == -32020 and to_http_status(ei.value) == 400


async def test_modern_headers_on_legacy_body_rejected() -> None:
    guard = CoSAIGuard([EnvelopeEngine()])
    req = make_request("tools/call", {"name": "delete_all"},
                       {"Mcp-Method": "tools/call", "Mcp-Name": "read_only"})
    with pytest.raises(RequestMetadataError) as ei:
        await guard._run_request(_ctx(), req)
    assert ei.value.json_rpc_code == -32020


async def test_unsupported_version_carries_supported_list() -> None:
    guard = CoSAIGuard([EnvelopeEngine()])
    params = {"_meta": {META_PROTOCOL_VERSION: "1900-01-01"}}
    req = make_request("tools/list", params, {"MCP-Protocol-Version": "1900-01-01",
                                              "Mcp-Method": "tools/list"})
    with pytest.raises(RequestMetadataError) as ei:
        await guard._run_request(_ctx(), req)
    err = to_jsonrpc_error(ei.value)
    assert err["code"] == -32022 and err["data"]["supported"] == [MODERN_PROTOCOL_VERSION]


async def test_registered_tool_schemas_enforce_param_headers() -> None:
    guard = CoSAIGuard([EnvelopeEngine()])
    guard.register_tool_schemas([{"name": "sql", "inputSchema": {
        "type": "object",
        "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}}}])
    headers, params = _modern("tools/call", {"name": "sql", "arguments": {"region": "eu"}})
    await guard._run_request(_ctx(), make_request(
        "tools/call", params, {**headers, "Mcp-Param-Region": "eu"}))
    with pytest.raises(RequestMetadataError):
        await guard._run_request(_ctx(), make_request(
            "tools/call", params, {**headers, "Mcp-Param-Region": "us"}))


# --- ASGI adapter end to end -----------------------------------------------------


async def _echo(request: Request) -> JSONResponse:
    payload = json.loads(await request.body() or b"{}")
    return JSONResponse({"jsonrpc": "2.0", "id": payload.get("id"), "result": {}})


def _client() -> httpx.AsyncClient:
    inner = Starlette(routes=[Route("/{path:path}", _echo, methods=["POST"])])
    app = ArmorMiddleware(inner, CoSAIGuard([SessionEngine(), EnvelopeEngine()]))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                             base_url="http://testserver")


async def _session(client: httpx.AsyncClient) -> str:
    init = await client.post("/", json={"jsonrpc": "2.0", "id": 0, "method": "initialize"})
    return init.headers["mcp-session-id"]


async def test_asgi_duplicate_routing_header_rejected_with_400() -> None:
    async with _client() as client:
        sid = await _session(client)
        headers, params = _modern("tools/list", {})
        pairs = [*headers.items(), ("Mcp-Method", "tools/call"),
                 ("mcp-session-id", sid), ("content-type", "application/json")]
        resp = await client.post("/", content=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params}),
            headers=pairs)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32020


async def test_asgi_meta_identity_claim_rejected_and_clean_request_passes() -> None:
    async with _client() as client:
        sid = await _session(client)
        bad = await client.post("/", headers={"mcp-session-id": sid}, json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": {"_meta": {"acme/tenant_id": "victim"}}})
        ok = await client.post("/", headers={"mcp-session-id": sid}, json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert bad.json()["error"]["code"] == -32002
    assert "error" not in ok.json()


async def test_regression_envelope_autoregisters_schemas_from_tools_list_response() -> None:
    from types import MappingProxyType

    from mcp_armor.types import MCPResponse

    guard = CoSAIGuard([EnvelopeEngine()])
    tools = [{"name": "sql", "inputSchema": {
        "type": "object",
        "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}}}]
    resp = MCPResponse(result=MappingProxyType({"tools": tools}), error=None, raw_body="x")
    await guard._run_request(_ctx(), make_request("tools/list", {}))
    await guard._run_response(_ctx(), resp)
    headers, params = _modern("tools/call", {"name": "sql", "arguments": {"region": "eu"}})
    await guard._run_request(_ctx(), make_request(
        "tools/call", params, {**headers, "Mcp-Param-Region": "eu"}))
    with pytest.raises(RequestMetadataError):
        await guard._run_request(_ctx(), make_request(
            "tools/call", params, {**headers, "Mcp-Param-Region": "us"}))


async def test_regression_envelope_dispatcher_modern_meta_not_rejected_for_rpc_transport(
) -> None:
    calls: list[dict[str, Any]] = []

    async def inner(payload: dict[str, Any]) -> dict[str, Any]:
        calls.append(payload)
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {}}

    protected = CoSAIGuard([EnvelopeEngine()]).wrap_dispatcher(inner)
    ok = await protected({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                          "params": {"_meta": dict(_META)}})
    assert "error" not in ok and len(calls) == 1
    bad = await protected({"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                           "params": {"_meta": {"zz_tenant_x": "victim"}}})
    assert bad["error"]["code"] == -32002 and len(calls) == 1


async def test_regression_dispatcher_envelope_errors_are_opaque() -> None:
    async def inner(payload: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {}}

    protected = CoSAIGuard([EnvelopeEngine()]).wrap_dispatcher(inner)
    bad = await protected({"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                           "params": {"_meta": {"zz_tenant_x": "victim"}}})
    assert "zz_tenant_x" not in json.dumps(bad)


async def test_exploit_envelope_empty_registry_missing_param_header() -> None:
    guard = CoSAIGuard([EnvelopeEngine()])          # no tools/list observed yet
    headers, params = _modern("tools/call", {"name": "pay", "arguments": {"account": "v"}})
    with pytest.raises(RequestMetadataError) as ei:
        await guard._run_request(_ctx(), make_request("tools/call", params, headers))
    assert ei.value.json_rpc_code == -32602


async def test_exploit_envelope_unknown_tool_oracle() -> None:
    from mcp_armor.engines.authz import AuthzEngine

    guard = CoSAIGuard([AuthzEngine(default_deny=True), EnvelopeEngine()])
    guard.register_tool_schemas([{"name": "admin_purge", "inputSchema": {"type": "object"}}])
    outcomes = []
    for name in ("admin_purge", "nonexistent_tool"):
        headers, params = _modern("tools/call", {"name": name, "arguments": {}})
        with pytest.raises(AuthorizationError) as ei:
            await guard._run_request(_ctx(), make_request("tools/call", params, headers))
        outcomes.append((type(ei.value), ei.value.json_rpc_code))
    assert outcomes[0] == outcomes[1]


def test_exploit_envelope_inert_paths_warn(caplog: pytest.LogCaptureFixture) -> None:
    from mcp_armor.adapters.fastmcp import _GuardedToolDispatcher

    guard = CoSAIGuard([EnvelopeEngine()])
    with caplog.at_level("WARNING"):
        _GuardedToolDispatcher(guard)
        guard.wrap_dispatcher(lambda p: p)
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "per-tool hook" in text and "wrap_dispatcher" in text


async def test_regression_protect_warns_envelope_inert(caplog: pytest.LogCaptureFixture) -> None:
    guard = CoSAIGuard([EnvelopeEngine()])
    with caplog.at_level("WARNING", logger="mcp_armor.guard"):
        @guard.protect(allow_unauthenticated=True)
        async def tool() -> str:
            return "ran"
    assert any("enforce_request_envelope" in r.getMessage() for r in caplog.records)
    assert await tool() == "ran"


_SQL_TOOL = {"name": "sql", "inputSchema": {"type": "object", "properties": {
    "region": {"type": "string", "x-mcp-header": "Region"}}}}
_HIDDEN_TOOL = {"name": "admin_purge", "inputSchema": {"type": "object"}}


async def _tools_app(request: Request) -> JSONResponse:
    payload = json.loads(await request.body() or b"{}")
    result: dict[str, Any] = {}
    if payload.get("method") == "tools/list":
        result = {"tools": [_SQL_TOOL, _HIDDEN_TOOL]}
    return JSONResponse({"jsonrpc": "2.0", "id": payload.get("id"), "result": result})


async def test_regression_envelope_asgi_tools_list_autoregister_and_t2_ordering() -> None:
    from mcp_armor.config import ToolPolicy
    from mcp_armor.engines.authz import AuthzEngine

    authz = AuthzEngine(tool_policies={
        "sql": ToolPolicy(required_scopes=(), user_only=False, destructive=False,
                          tenant_isolated=False),
        "admin_purge": ToolPolicy(required_scopes=("admin",), user_only=False,
                                  destructive=False, tenant_isolated=False)})
    inner = Starlette(routes=[Route("/{path:path}", _tools_app, methods=["POST"])])
    app = ArmorMiddleware(inner, CoSAIGuard([SessionEngine(), authz, EnvelopeEngine()]))

    def call(name: str, args: dict[str, Any], extra: dict[str, str]) -> tuple[Any, Any]:
        headers, params = _modern("tools/call", {"name": name, "arguments": args})
        return {**headers, **extra}, {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                                      "params": params}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://testserver") as client:
        sid = await _session(client)
        base = {"mcp-session-id": sid}
        # (c) before tools/list: modern call fails closed; legacy call passes
        h, b = call("sql", {"region": "eu"}, {"Mcp-Param-Region": "eu"})
        r = await client.post("/", headers={**base, **h}, json=b)
        assert r.status_code == 400 and r.json()["error"]["code"] == -32602
        r = await client.post("/", headers=base, json={
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": {"name": "sql", "arguments": {"region": "eu"}}})
        assert "error" not in r.json()
        await client.post("/", headers=base, json={"jsonrpc": "2.0", "id": 7,
                                                   "method": "tools/list", "params": {}})
        # (a) consistent header passes
        r = await client.post("/", headers={**base, **h}, json=b)
        assert r.status_code == 200 and "error" not in r.json()
        # (b) mismatched header rejected
        h2, b2 = call("sql", {"region": "eu"}, {"Mcp-Param-Region": "us"})
        r = await client.post("/", headers={**base, **h2}, json=b2)
        assert r.status_code == 400 and r.json()["error"]["code"] == -32020
        # (d) hidden tool: T2 answers first, identical to a nonexistent tool
        codes = []
        for name in ("admin_purge", "nonexistent"):
            h3, b3 = call(name, {}, {})
            r = await client.post("/", headers={**base, **h3}, json=b3)
            codes.append((r.status_code, r.json()["error"]["code"]))
        assert codes[0] == codes[1] == (200, -32002)


async def test_exploit_envelope_registry_not_overwritten_by_later_manifest() -> None:
    from types import MappingProxyType

    from mcp_armor.types import MCPResponse

    def manifest(prop: str) -> MCPResponse:
        tool = {"name": "sql", "inputSchema": {"type": "object", "properties": {
            prop: {"type": "string", "x-mcp-header": "Region"}}}}
        return MCPResponse(result=MappingProxyType({"tools": [tool]}), error=None,
                           raw_body="x")

    guard = CoSAIGuard([EnvelopeEngine()])
    await guard._run_request(_ctx(), make_request("tools/list", {}))
    await guard._run_response(_ctx(), manifest("region"))          # A: first observed
    await guard._run_request(_ctx(), make_request("tools/list", {}))
    await guard._run_response(_ctx(), manifest("note"))            # B: remap attempt
    await guard._run_request(_ctx(), make_request("tools/call", {"name": "x"}))
    await guard._run_response(_ctx(), manifest("other"))           # non-tools/list result
    headers, params = _modern("tools/call", {"name": "sql",
                                             "arguments": {"region": "eu", "note": "us"}})
    with pytest.raises(RequestMetadataError) as ei:
        await guard._run_request(_ctx(), make_request(
            "tools/call", params, {**headers, "Mcp-Param-Region": "us"}))
    assert ei.value.json_rpc_code == -32020


async def test_regression_envelope_operator_pin_wins_and_non_list_ignored() -> None:
    from types import MappingProxyType

    from mcp_armor.types import MCPResponse

    guard = CoSAIGuard([EnvelopeEngine()])
    guard.register_tool_schemas([_SQL_TOOL])
    other = {"name": "sql", "inputSchema": {"type": "object"}}
    await guard._run_request(_ctx(), make_request("tools/list", {}))
    await guard._run_response(_ctx(), MCPResponse(
        result=MappingProxyType({"tools": [other]}), error=None, raw_body="x"))
    engine = guard._engines[0]
    assert isinstance(engine, EnvelopeEngine)
    assert engine._tool_schemas["sql"] == _SQL_TOOL["inputSchema"]
    await guard._run_request(_ctx(), make_request("tools/call", {"name": "x"}))
    await guard._run_response(_ctx(), MCPResponse(
        result=MappingProxyType({"tools": [{"name": "new", "inputSchema": {}}]}),
        error=None, raw_body="x"))
    assert "new" not in engine._tool_schemas


async def test_regression_envelope_registry_cap_bounded_and_warns(
        caplog: pytest.LogCaptureFixture) -> None:
    from mcp_armor.engines import envelope as env_mod

    guard = CoSAIGuard([EnvelopeEngine()])
    engine = guard._engines[0]
    assert isinstance(engine, EnvelopeEngine)
    cap = env_mod._MAX_REGISTERED_TOOLS
    tools = [{"name": f"t{i}", "inputSchema": {"type": "object"}} for i in range(cap + 5)]
    with caplog.at_level("WARNING", logger="mcp_armor.engines.envelope"):
        guard.register_tool_schemas(tools)
        guard.register_tool_schemas(tools)
    assert len(engine._tool_schemas) == cap and f"t{cap - 1}" in engine._tool_schemas
    warnings = [r for r in caplog.records if "registry is full" in r.getMessage()]
    assert len(warnings) == 1 and f"t{cap}" not in warnings[0].getMessage()
    headers, params = _modern("tools/call", {"name": f"t{cap}", "arguments": {}})
    with pytest.raises(RequestMetadataError) as ei:
        await guard._run_request(_ctx(), make_request("tools/call", params, headers))
    assert ei.value.json_rpc_code == -32602


async def test_regression_envelope_current_method_is_per_task() -> None:
    import asyncio
    from types import MappingProxyType

    from mcp_armor.types import MCPResponse

    guard = CoSAIGuard([EnvelopeEngine()])
    engine = guard._engines[0]
    assert isinstance(engine, EnvelopeEngine)
    resp = MCPResponse(result=MappingProxyType({"tools": [_SQL_TOOL]}), error=None,
                       raw_body="x")
    a_listed = asyncio.Event()
    b_done = asyncio.Event()

    async def task_a() -> None:
        await guard._run_request(_ctx(), make_request("tools/list", {}))
        a_listed.set()
        await b_done.wait()
        await guard._run_response(_ctx(), resp)

    async def task_b() -> None:
        await a_listed.wait()
        await guard._run_request(_ctx(), make_request("tools/call", {"name": "x"}))
        await guard._run_response(_ctx(), resp)
        assert engine._tool_schemas == {}
        b_done.set()

    await asyncio.gather(asyncio.create_task(task_a()), asyncio.create_task(task_b()))
    assert "sql" in engine._tool_schemas

    fresh = CoSAIGuard([EnvelopeEngine()])
    eng2 = fresh._engines[0]
    assert isinstance(eng2, EnvelopeEngine)

    async def same_task() -> None:
        await fresh._run_request(_ctx(), make_request("tools/list", {}))
        await fresh._run_request(_ctx(), make_request("tools/call", {"name": "x"}))
        await fresh._run_response(_ctx(), resp)

    await asyncio.create_task(same_task())
    assert eng2._tool_schemas == {}


_ACCT = {"name": "transfer", "inputSchema": {"type": "object", "properties": {
    "account": {"type": "string", "x-mcp-header": "Account"}},
    "required": ["account"], "additionalProperties": False}}


def _manifest_app(manifests: list[list[dict[str, Any]]]) -> Starlette:
    async def handler(request: Request) -> JSONResponse:
        payload = json.loads(await request.body() or b"{}")
        result: dict[str, Any] = {}
        if payload.get("method") == "tools/list":
            result = {"tools": manifests.pop(0)}
        elif payload.get("method") == "tools/call":
            result = ({"tools": [{"name": "transfer", "inputSchema": {}}]}
                      if payload["params"]["name"] == "lookup" else {})
        return JSONResponse({"jsonrpc": "2.0", "id": payload.get("id"), "result": result})

    return Starlette(routes=[Route("/{path:path}", handler, methods=["POST"])])


async def test_exploit_envelope_registry_not_pinned_by_rejected_manifest() -> None:
    from mcp_armor.engines.supply_chain import SupplyChainEngine
    from mcp_armor.engines.validation import ValidationEngine

    stripped = {"name": "transfer", "inputSchema": {"type": "object"}}
    inner = _manifest_app([[stripped, {"name": "evil_tool", "inputSchema": {}}], [_ACCT]])
    guard = CoSAIGuard([SessionEngine(), SupplyChainEngine(tool_allowlist=["transfer"]),
                        EnvelopeEngine(), ValidationEngine(strict_schema=True)])
    app = ArmorMiddleware(inner, guard)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://testserver") as client:
        sid = await _session(client)
        base = {"mcp-session-id": sid}
        tl = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        rejected = await client.post("/", headers=base, json=tl)
        assert rejected.json()["error"]["code"] == -32011
        await client.post("/", headers=base, json=tl)            # legitimate manifest
        headers, params = _modern("tools/call", {"name": "transfer",
                                                 "arguments": {"account": "victim"}})
        r = await client.post("/", headers={**base, **headers}, json={
            "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": params})
        assert r.status_code == 400 and r.json()["error"]["code"] == -32020
        r = await client.post("/", headers=base, json={
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "transfer", "arguments": {"account": 5}}})
        assert r.json()["error"]["code"] == -32602                # T3 kept the real schema


async def test_exploit_validation_registry_not_fed_by_non_tools_list_result() -> None:
    from mcp_armor.engines.validation import ValidationEngine

    inner = _manifest_app([[_ACCT, {"name": "lookup", "inputSchema": {}}]])
    guard = CoSAIGuard([SessionEngine(), ValidationEngine(strict_schema=True)])
    app = ArmorMiddleware(inner, guard)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://testserver") as client:
        sid = await _session(client)
        base = {"mcp-session-id": sid}
        # a tools/call whose result carries a top-level "tools" key comes first —
        # it must not register anything (and lookup itself is unknown yet)
        await client.post("/", headers=base, json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "lookup", "arguments": {}}})
        await client.post("/", headers=base, json={
            "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}})
        r = await client.post("/", headers=base, json={
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "transfer", "arguments": {"account": 5}}})
        assert r.json()["error"]["code"] == -32602


def _tools_resp(tools: list[dict[str, Any]]) -> Any:
    from types import MappingProxyType

    from mcp_armor.types import MCPResponse

    return MCPResponse(result=MappingProxyType({"tools": tools}), error=None, raw_body="x")


async def test_regression_inflight_method_not_leaked_across_requests() -> None:
    from mcp_armor.engines.validation import ValidationEngine

    val, env = ValidationEngine(), EnvelopeEngine()
    guard = CoSAIGuard([val, env])
    await guard._run_request(_ctx(), make_request("tools/list", {}))
    await guard._run_response(_ctx(), _tools_resp([]))
    await guard._run_response(_ctx(), _tools_resp([_SQL_TOOL]))   # no matching request
    assert val._tool_schemas == {} and env._tool_schemas == {}


async def test_regression_dry_run_violation_blocks_schema_commit(
        monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp_armor.engines.validation import ValidationEngine
    from mcp_armor.exceptions import PIILeakError

    class Raising:
        async def on_response(self, ctx: Any, resp: Any) -> Any:
            raise PIILeakError("x")

        async def on_request(self, ctx: Any, req: Any) -> Any:
            return ctx

    monkeypatch.setenv("ARMOR_ALLOW_DRY_RUN", "1")
    val = ValidationEngine()
    guard = CoSAIGuard([Raising(), val], dry_run=True)  # type: ignore[list-item]
    await guard._run_request(_ctx(), make_request("tools/list", {}))
    await guard._run_response(_ctx(), _tools_resp([_SQL_TOOL]))
    assert val._tool_schemas == {}
    clean_val = ValidationEngine()
    clean = CoSAIGuard([clean_val], dry_run=True)
    await clean._run_request(_ctx(), make_request("tools/list", {}))
    await clean._run_response(_ctx(), _tools_resp([_SQL_TOOL]))
    assert "sql" in clean_val._tool_schemas


async def test_regression_dispatcher_tools_list_commits_then_tools_call_validated() -> None:
    from mcp_armor.engines.validation import ValidationEngine

    async def inner(payload: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {"tools": [_ACCT]} if payload["method"] == "tools/list" else {}
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": result}

    protected = CoSAIGuard([ValidationEngine(strict_schema=True)]).wrap_dispatcher(inner)
    await protected({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    bad = await protected({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                           "params": {"name": "transfer", "arguments": {"account": 5}}})
    assert bad["error"]["code"] == -32602
    ok = await protected({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                          "params": {"name": "transfer", "arguments": {"account": "a"}}})
    assert "error" not in ok
