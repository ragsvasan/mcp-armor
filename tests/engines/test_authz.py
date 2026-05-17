"""Tests for T2 AuthzEngine — RBAC, confused deputy, tenant isolation, destructive gate."""

from __future__ import annotations

import uuid

import pytest

from mcp_armor.config import ToolPolicy
from mcp_armor.context import CoSAIContext
from mcp_armor.engines.authz import AuthzEngine, _TokenStore
from mcp_armor.exceptions import AuthorizationError
from tests.conftest import make_ctx, make_request


def _policy(**kwargs) -> ToolPolicy:
    defaults = dict(required_scopes=(), user_only=False, destructive=False, tenant_isolated=False)
    defaults.update(kwargs)
    return ToolPolicy(**defaults)


def _engine(policies=None, default_deny=True, ttl=60, echo_confirm_token=False) -> AuthzEngine:
    return AuthzEngine(
        tool_policies=policies or {},
        default_deny=default_deny,
        destructive_token_ttl_seconds=ttl,
        echo_confirm_token=echo_confirm_token,
    )


def _ctx_with_user(user_id: str = "u1", tenant_id: str | None = "t1",
                   scopes: tuple[str, ...] = ()) -> CoSAIContext:
    return make_ctx().with_user(user_id, tenant_id).with_scopes(scopes)


# ---------------------------------------------------------------------------
# Default-deny gate (T2-001 baseline)
# ---------------------------------------------------------------------------

async def test_default_deny_unlisted_tool() -> None:
    eng = _engine(default_deny=True)
    req = make_request(params={"name": "unknown_tool", "arguments": {}})
    with pytest.raises(AuthorizationError, match="not in policy"):
        await eng.on_request(_ctx_with_user(), req)


async def test_default_allow_unlisted_tool_passes() -> None:
    eng = _engine(default_deny=False)
    req = make_request(params={"name": "any_tool", "arguments": {}})
    ctx = await eng.on_request(_ctx_with_user(), req)
    assert ctx is not None


async def test_non_tools_call_method_skipped() -> None:
    eng = _engine(default_deny=True)
    req = make_request(method="tools/list", params={})
    ctx = await eng.on_request(make_ctx(), req)
    assert ctx is not None


# ---------------------------------------------------------------------------
# T2-001: required_scopes subset check
# ---------------------------------------------------------------------------

async def test_required_scope_present_passes() -> None:
    eng = _engine(policies={"q": _policy(required_scopes=("read:public",))})
    ctx = _ctx_with_user(scopes=("read:public", "write:own"))
    req = make_request(params={"name": "q", "arguments": {}})
    result = await eng.on_request(ctx, req)
    assert result is not None


async def test_missing_required_scope_denied() -> None:
    eng = _engine(policies={"q": _policy(required_scopes=("admin",))})
    ctx = _ctx_with_user(scopes=("read:public",))
    req = make_request(params={"name": "q", "arguments": {}})
    with pytest.raises(AuthorizationError, match="admin"):
        await eng.on_request(ctx, req)


async def test_multiple_scopes_all_must_be_present() -> None:
    eng = _engine(policies={"op": _policy(required_scopes=("read:data", "write:data"))})
    # Only one scope present
    ctx = _ctx_with_user(scopes=("read:data",))
    req = make_request(params={"name": "op", "arguments": {}})
    with pytest.raises(AuthorizationError, match="write:data"):
        await eng.on_request(ctx, req)


async def test_empty_required_scopes_always_passes() -> None:
    eng = _engine(policies={"free": _policy(required_scopes=())})
    ctx = _ctx_with_user(scopes=())
    req = make_request(params={"name": "free", "arguments": {}})
    result = await eng.on_request(ctx, req)
    assert result is not None


# ---------------------------------------------------------------------------
# T2-002: confused deputy
# ---------------------------------------------------------------------------

async def test_user_only_tool_with_user_passes() -> None:
    eng = _engine(policies={"priv": _policy(user_only=True)})
    ctx = _ctx_with_user(user_id="alice")
    req = make_request(params={"name": "priv", "arguments": {}})
    result = await eng.on_request(ctx, req)
    assert result is not None


async def test_user_only_tool_without_user_denied() -> None:
    eng = _engine(policies={"priv": _policy(user_only=True)})
    ctx = make_ctx()  # no user_id set
    req = make_request(params={"name": "priv", "arguments": {}})
    with pytest.raises(AuthorizationError, match="user identity"):
        await eng.on_request(ctx, req)


async def test_user_only_tool_empty_user_id_denied() -> None:
    eng = _engine(policies={"priv": _policy(user_only=True)})
    ctx = make_ctx().with_user("")
    req = make_request(params={"name": "priv", "arguments": {}})
    with pytest.raises(AuthorizationError, match="user identity"):
        await eng.on_request(ctx, req)


# ---------------------------------------------------------------------------
# T2-003: tenant isolation
# ---------------------------------------------------------------------------

async def test_tenant_isolated_matching_tenant_passes() -> None:
    eng = _engine(policies={"t_op": _policy(tenant_isolated=True)})
    ctx = _ctx_with_user(tenant_id="acme")
    req = make_request(params={"name": "t_op", "arguments": {"tenant_id": "acme"}})
    result = await eng.on_request(ctx, req)
    assert result is not None


async def test_tenant_isolated_mismatched_tenant_denied() -> None:
    eng = _engine(policies={"t_op": _policy(tenant_isolated=True)})
    ctx = _ctx_with_user(tenant_id="acme")
    req = make_request(params={"name": "t_op", "arguments": {"tenant_id": "evil-corp"}})
    with pytest.raises(AuthorizationError, match="cross-tenant"):
        await eng.on_request(ctx, req)


async def test_regression_tenant_isolated_no_arg_tenant_denied() -> None:
    # Panel finding: tenant_isolated=True + absent tenant_id must be default-deny
    eng = _engine(policies={"t_op": _policy(tenant_isolated=True)})
    ctx = _ctx_with_user(tenant_id="acme")
    req = make_request(params={"name": "t_op", "arguments": {}})
    with pytest.raises(AuthorizationError, match="tenant_id"):
        await eng.on_request(ctx, req)


# ---------------------------------------------------------------------------
# T2-004: destructive two-stage commit gate
# ---------------------------------------------------------------------------

async def test_destructive_tool_no_token_denied() -> None:
    eng = _engine(policies={"nuke": _policy(destructive=True)})
    req = make_request(params={"name": "nuke", "arguments": {}})
    with pytest.raises(AuthorizationError, match="_confirm_token"):
        await eng.on_request(_ctx_with_user(), req)


async def test_destructive_tool_token_issued_in_error() -> None:
    eng = _engine(policies={"nuke": _policy(destructive=True)})
    req = make_request(params={"name": "nuke", "arguments": {}})
    ctx = _ctx_with_user()
    with pytest.raises(AuthorizationError) as exc_info:
        await eng.on_request(ctx, req)
    # Error message must contain the token for re-submission
    assert "_confirm_token" in str(exc_info.value)


async def test_destructive_tool_valid_token_passes() -> None:
    # echo_confirm_token=True: interactive-client mode where the token is
    # returned in the error for a human to re-submit (F9 opt-in).
    eng = _engine(policies={"nuke": _policy(destructive=True)}, echo_confirm_token=True)
    ctx = _ctx_with_user()

    # First call — get the token from the error
    req1 = make_request(params={"name": "nuke", "arguments": {}})
    with pytest.raises(AuthorizationError) as exc_info:
        await eng.on_request(ctx, req1)

    # Extract the token from the error message
    msg = str(exc_info.value)
    # Token is between single quotes after '_confirm_token':
    import re
    match = re.search(r"'_confirm_token': '([^']+)'", msg)
    assert match, f"Could not extract token from: {msg}"
    token = match.group(1)

    # Second call — with the correct token
    req2 = make_request(params={"name": "nuke", "arguments": {"_confirm_token": token}})
    result = await eng.on_request(ctx, req2)
    assert result is not None


async def test_destructive_tool_wrong_token_denied() -> None:
    eng = _engine(policies={"nuke": _policy(destructive=True)})
    ctx = _ctx_with_user()

    # Issue a real token first (so one is in the store)
    req1 = make_request(params={"name": "nuke", "arguments": {}})
    with pytest.raises(AuthorizationError):
        await eng.on_request(ctx, req1)

    # Submit with wrong token
    req2 = make_request(params={"name": "nuke", "arguments": {"_confirm_token": "bad-token"}})
    with pytest.raises(AuthorizationError, match="invalid or expired"):
        await eng.on_request(ctx, req2)


async def test_destructive_token_single_use() -> None:
    eng = _engine(policies={"nuke": _policy(destructive=True)}, echo_confirm_token=True)
    ctx = _ctx_with_user()

    req1 = make_request(params={"name": "nuke", "arguments": {}})
    with pytest.raises(AuthorizationError) as exc_info:
        await eng.on_request(ctx, req1)

    import re
    token = re.search(r"'_confirm_token': '([^']+)'", str(exc_info.value)).group(1)  # type: ignore

    # Use token once — should succeed
    req2 = make_request(params={"name": "nuke", "arguments": {"_confirm_token": token}})
    await eng.on_request(ctx, req2)

    # Use same token again — should fail (single-use)
    with pytest.raises(AuthorizationError, match="invalid or expired"):
        await eng.on_request(ctx, req2)


# ---------------------------------------------------------------------------
# _TokenStore unit tests
# ---------------------------------------------------------------------------

def test_token_store_issue_and_consume() -> None:
    store = _TokenStore(ttl_seconds=60)
    sid = str(uuid.uuid4())
    token = store.issue(sid, "my_tool")
    assert store.consume(sid, "my_tool", token) is True


def test_token_store_wrong_token_fails() -> None:
    store = _TokenStore(ttl_seconds=60)
    sid = str(uuid.uuid4())
    store.issue(sid, "my_tool")
    assert store.consume(sid, "my_tool", "wrong") is False


def test_token_store_missing_session_fails() -> None:
    store = _TokenStore(ttl_seconds=60)
    assert store.consume("no-such-session", "tool", "any-token") is False


def test_token_store_expired_fails() -> None:
    import time
    store = _TokenStore(ttl_seconds=0)  # immediate expiry
    sid = str(uuid.uuid4())
    token = store.issue(sid, "my_tool")
    time.sleep(0.01)
    assert store.consume(sid, "my_tool", token) is False


def test_token_store_reissue_replaces_old_token() -> None:
    store = _TokenStore(ttl_seconds=60)
    sid = str(uuid.uuid4())
    old_token = store.issue(sid, "tool_a")
    new_token = store.issue(sid, "tool_a")
    assert store.consume(sid, "tool_a", old_token) is False  # old token invalidated
    assert store.consume(sid, "tool_a", new_token) is True


# ---------------------------------------------------------------------------
# Panel regression tests — P0 and P1 findings
# ---------------------------------------------------------------------------

def test_regression_dummy_compare_uses_fixed_length_secret() -> None:
    """FIX-2: consume() must compare against a fixed-length dummy, not self-referential."""
    store = _TokenStore(ttl_seconds=60)
    # No entry for this session — compare must NOT be compare_digest(x, x)
    # Verify by checking the dummy is a real, non-trivially-short string
    assert len(store._dummy) == 43  # token_urlsafe(32) always → 43 chars
    # A wrong token of a different length must still return False without raising
    result = store.consume("no-session", "tool", "x")
    assert result is False


def test_regression_token_bound_to_tool_name() -> None:
    """FIX-6 (Sonnet): token issued for tool_a must not be consumable for tool_b."""
    store = _TokenStore(ttl_seconds=60)
    sid = str(uuid.uuid4())
    token = store.issue(sid, "tool_a")
    # Same session, different tool — must fail
    assert store.consume(sid, "tool_b", token) is False
    # Correct tool — must succeed
    assert store.consume(sid, "tool_a", token) is True


async def test_regression_confirm_token_not_transferable_across_tools() -> None:
    """FIX-4 (Opus): token obtained for nuke_a cannot execute nuke_b in the same session."""
    eng = _engine(policies={
        "nuke_a": _policy(destructive=True),
        "nuke_b": _policy(destructive=True),
    }, echo_confirm_token=True)
    ctx = _ctx_with_user()
    import re

    # Get token for nuke_a
    req_a = make_request(params={"name": "nuke_a", "arguments": {}})
    with pytest.raises(AuthorizationError) as exc_info:
        await eng.on_request(ctx, req_a)
    token_a = re.search(r"'_confirm_token': '([^']+)'", str(exc_info.value)).group(1)  # type: ignore

    # Try to use nuke_a's token on nuke_b — must fail
    req_b = make_request(params={"name": "nuke_b", "arguments": {"_confirm_token": token_a}})
    with pytest.raises(AuthorizationError, match="invalid or expired"):
        await eng.on_request(ctx, req_b)


def test_regression_token_store_evicts_expired_entries() -> None:
    """FIX-7 (Sonnet): issue() lazily evicts expired entries."""
    import time
    store = _TokenStore(ttl_seconds=0)  # immediate expiry
    sid = str(uuid.uuid4())
    for i in range(5):
        store.issue(sid, f"tool_{i}")
    time.sleep(0.05)
    # Next issue() triggers eviction
    store.issue(sid, "fresh_tool")
    with store._lock:
        assert len(store._entries) == 1  # only the fresh entry remains


def test_regression_confirm_token_non_string_types_denied() -> None:
    """FIX-10 (Sonnet): non-string _confirm_token types must not bypass the gate."""
    store = _TokenStore(ttl_seconds=60)
    sid = str(uuid.uuid4())
    store.issue(sid, "tool")
    # str(None) → "None", str(0) → "0" — neither matches a real token
    assert store.consume(sid, "tool", str(None)) is False
    # Re-issue since first consume fails (token not consumed)
    store.issue(sid, "tool")
    assert store.consume(sid, "tool", str(0)) is False


# ---------------------------------------------------------------------------
# T2-004b: filter_tools_list — scope-filtered manifest (cosai-mcp T02-004)
# ---------------------------------------------------------------------------

def test_filter_tools_list_hides_tool_requiring_missing_scope() -> None:
    """Caller without write scope must not see tools that require it."""
    eng = _engine(
        policies={
            "read_data": _policy(required_scopes=("data:read",)),
            "write_data": _policy(required_scopes=("data:write",)),
        },
        default_deny=False,
    )
    ctx = _ctx_with_user(scopes=("data:read",))
    visible = eng.filter_tools_list(["read_data", "write_data"], ctx)
    assert visible == ["read_data"]


def test_filter_tools_list_shows_all_when_caller_has_all_scopes() -> None:
    """Caller with all scopes sees all tools."""
    eng = _engine(
        policies={
            "read_data": _policy(required_scopes=("data:read",)),
            "write_data": _policy(required_scopes=("data:write",)),
        },
        default_deny=False,
    )
    ctx = _ctx_with_user(scopes=("data:read", "data:write"))
    visible = eng.filter_tools_list(["read_data", "write_data"], ctx)
    assert set(visible) == {"read_data", "write_data"}


def test_filter_tools_list_default_deny_hides_unknown_tools() -> None:
    """With default_deny=True, tools not in policy are hidden from the manifest."""
    eng = _engine(
        policies={"allowed": _policy()},
        default_deny=True,
    )
    ctx = _ctx_with_user()
    visible = eng.filter_tools_list(["allowed", "unknown_tool"], ctx)
    assert visible == ["allowed"]


def test_filter_tools_list_default_allow_shows_unknown_tools() -> None:
    """With default_deny=False, tools not in policy are visible to all callers."""
    eng = _engine(policies={}, default_deny=False)
    ctx = _ctx_with_user()
    visible = eng.filter_tools_list(["any_tool", "another_tool"], ctx)
    assert set(visible) == {"any_tool", "another_tool"}


def test_filter_tools_list_empty_input_returns_empty() -> None:
    eng = _engine(default_deny=False)
    ctx = _ctx_with_user()
    assert eng.filter_tools_list([], ctx) == []


def test_filter_tools_list_hides_admin_tools_from_read_only_caller() -> None:
    """Read-only caller must not discover admin/purge tool names (T02-004 D-05)."""
    eng = _engine(
        policies={
            "list_items": _policy(required_scopes=("items:read",)),
            "admin_reset": _policy(required_scopes=("admin",)),
            "purge_all": _policy(required_scopes=("admin",)),
        },
        default_deny=True,
    )
    ctx = _ctx_with_user(scopes=("items:read",))
    visible = eng.filter_tools_list(["list_items", "admin_reset", "purge_all"], ctx)
    assert visible == ["list_items"]
    assert "admin_reset" not in visible
    assert "purge_all" not in visible


def test_regression_filter_tools_list_no_authz_engine_passthrough() -> None:
    """CoSAIGuard.filter_tools_list returns all names when no AuthzEngine is configured."""
    from mcp_armor.guard import CoSAIGuard
    from mcp_armor.engines.session import SessionEngine
    guard = CoSAIGuard([SessionEngine(bind_to_dpop=False)])
    ctx = make_ctx()
    names = ["tool_a", "tool_b"]
    assert guard.filter_tools_list(names, ctx) == names
