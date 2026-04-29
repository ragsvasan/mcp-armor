"""Tests for T10 ResourceEngine — call budget, wall-clock, loop depth."""

from __future__ import annotations

import pytest

from mcp_armor.engines.resources import ResourceEngine
from mcp_armor.exceptions import ResourceExceededError
from tests.conftest import make_ctx, make_request


def _engine(**kwargs) -> ResourceEngine:
    defaults = dict(max_calls_per_session=5, max_wall_clock_secs=300.0,
                    loop_depth_limit=3, heartbeat_interval_secs=30.0)
    defaults.update(kwargs)
    return ResourceEngine(**defaults)


# ---------------------------------------------------------------------------
# T10-001: call budget
# ---------------------------------------------------------------------------

async def test_first_call_passes() -> None:
    eng = _engine()
    ctx = make_ctx()
    req = make_request(method="tools/call")
    result = await eng.on_request(ctx, req)
    assert result is not None


async def test_call_count_incremented() -> None:
    eng = _engine(max_calls_per_session=3)
    ctx = make_ctx()
    req = make_request(method="tools/call")
    ctx = await eng.on_request(ctx, req)
    assert ctx.budget.calls_used == 1
    ctx = await eng.on_request(ctx, req)
    assert ctx.budget.calls_used == 2


async def test_call_budget_exceeded_raises() -> None:
    eng = _engine(max_calls_per_session=2)
    ctx = make_ctx()
    req = make_request(method="tools/call")
    ctx = await eng.on_request(ctx, req)
    ctx = await eng.on_request(ctx, req)
    # 3rd call exceeds budget of 2
    with pytest.raises(ResourceExceededError, match="budget exhausted"):
        await eng.on_request(ctx, req)


async def test_non_tools_call_not_counted() -> None:
    eng = _engine(max_calls_per_session=1)
    ctx = make_ctx()
    # tools/list does not count against the budget
    req = make_request(method="tools/list")
    ctx = await eng.on_request(ctx, req)
    ctx = await eng.on_request(ctx, req)
    ctx = await eng.on_request(ctx, req)
    assert ctx.budget.calls_used == 0  # no increment


# ---------------------------------------------------------------------------
# T10-002: wall-clock limit
# ---------------------------------------------------------------------------

async def test_wall_clock_exceeded_raises() -> None:
    import time
    eng = _engine(max_wall_clock_secs=0.001)
    # Create a ctx whose budget.wall_clock_start is far in the past
    from mcp_armor.types import BudgetState
    ctx = make_ctx()
    # Patch the budget to simulate elapsed time
    old_budget = ctx.budget
    stale_budget = BudgetState(
        calls_used=0,
        wall_clock_start=old_budget.wall_clock_start - 10.0,  # 10 seconds ago
        loop_depth=0,
    )
    ctx = ctx.with_budget(stale_budget)
    req = make_request(method="tools/call")
    with pytest.raises(ResourceExceededError, match="wall-clock"):
        await eng.on_request(ctx, req)


# ---------------------------------------------------------------------------
# T10-003: loop depth
# ---------------------------------------------------------------------------

async def test_loop_depth_exceeded_raises() -> None:
    eng = _engine(loop_depth_limit=2)
    from mcp_armor.types import BudgetState
    ctx = make_ctx()
    # Set loop_depth beyond limit
    deep_budget = BudgetState(
        calls_used=0,
        wall_clock_start=ctx.budget.wall_clock_start,
        loop_depth=3,  # > limit of 2
    )
    ctx = ctx.with_budget(deep_budget)
    req = make_request(method="tools/call")
    with pytest.raises(ResourceExceededError, match="depth"):
        await eng.on_request(ctx, req)


async def test_loop_depth_at_limit_passes() -> None:
    eng = _engine(loop_depth_limit=3)
    from mcp_armor.types import BudgetState
    ctx = make_ctx()
    budget = BudgetState(calls_used=0, wall_clock_start=ctx.budget.wall_clock_start, loop_depth=3)
    ctx = ctx.with_budget(budget)
    req = make_request(method="tools/call")
    # depth == limit (not >) should pass
    result = await eng.on_request(ctx, req)
    assert result is not None


# ---------------------------------------------------------------------------
# Lifecycle hooks
# ---------------------------------------------------------------------------

async def test_on_response_passthrough() -> None:
    eng = _engine()
    from tests.conftest import make_response
    ctx = make_ctx()
    resp = make_response("ok")
    result = await eng.on_response(ctx, resp)
    assert result is ctx


async def test_on_session_start_passthrough() -> None:
    eng = _engine()
    ctx = make_ctx()
    result = await eng.on_session_start(ctx)
    assert result is ctx
