"""Per-request async context — one CoSAIContext per live session, no global state."""

from __future__ import annotations

import time
from contextvars import ContextVar
from dataclasses import dataclass, replace

from .types import BudgetState, Finding


@dataclass(frozen=True)
class CoSAIContext:
    session_id: str
    user_id: str | None
    tenant_id: str | None
    tool_manifest_hash: str        # T6: SHA-256 of tools/list response at initialize
    budget: BudgetState            # T10: call + time tracking
    audit_parent_id: str | None    # T12: DAG parent for nested calls
    findings: tuple[Finding, ...]  # accumulated across all engines this request

    @classmethod
    def new(cls, session_id: str) -> "CoSAIContext":
        return cls(
            session_id=session_id,
            user_id=None,
            tenant_id=None,
            tool_manifest_hash="",
            budget=BudgetState(calls_used=0, wall_clock_start=time.monotonic(), loop_depth=0),
            audit_parent_id=None,
            findings=(),
        )

    def with_finding(self, finding: Finding) -> "CoSAIContext":
        return replace(self, findings=(*self.findings, finding))

    def with_user(self, user_id: str, tenant_id: str | None = None) -> "CoSAIContext":
        return replace(self, user_id=user_id, tenant_id=tenant_id)

    def with_manifest_hash(self, h: str) -> "CoSAIContext":
        return replace(self, tool_manifest_hash=h)

    def with_budget(self, budget: BudgetState) -> "CoSAIContext":
        return replace(self, budget=budget)

    def with_audit_parent(self, parent_id: str) -> "CoSAIContext":
        return replace(self, audit_parent_id=parent_id)


_ctx_var: ContextVar[CoSAIContext] = ContextVar("cosai_context")


def get_context() -> CoSAIContext:
    return _ctx_var.get()


def set_context(ctx: CoSAIContext) -> None:
    _ctx_var.set(ctx)


def has_context() -> bool:
    try:
        _ctx_var.get()
        return True
    except LookupError:
        return False
