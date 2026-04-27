"""Shared types for mcp-armor — frozen dataclasses only, no mutable containers."""

from __future__ import annotations

import html
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"
    T5 = "T5"
    T6 = "T6"
    T7 = "T7"
    T8 = "T8"
    T9 = "T9"
    T10 = "T10"
    T11 = "T11"
    T12 = "T12"


@dataclass(frozen=True)
class Finding:
    threat: ThreatCategory
    severity: Severity
    code: str                  # e.g. "T1-001"
    message: str               # human-readable, no PII
    location: str              # where in the request/response
    remediation: str


@dataclass(frozen=True)
class MCPRequest:
    method: str                        # e.g. "tools/call"
    params: MappingProxyType[str, Any]
    session_id: str
    raw_headers: MappingProxyType[str, str]

    @classmethod
    def from_dict(cls, d: dict[str, Any], session_id: str, headers: dict[str, str]) -> "MCPRequest":
        return cls(
            method=str(d.get("method", "")),
            params=MappingProxyType(dict(d.get("params", {}))),
            session_id=session_id,
            raw_headers=MappingProxyType(headers),
        )


@dataclass(frozen=True)
class MCPResponse:
    result: MappingProxyType[str, Any] | None
    error: MappingProxyType[str, Any] | None
    raw_body: str              # HTML-escaped at ingestion

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "MCPResponse":
        raw = str(d)
        return cls(
            result=MappingProxyType(d["result"]) if "result" in d else None,
            error=MappingProxyType(d["error"]) if "error" in d else None,
            raw_body=html.escape(raw[:65536], quote=True),  # cap + escape at ingestion
        )


@dataclass(frozen=True)
class BudgetState:
    calls_used: int
    wall_clock_start: float    # time.monotonic() at session start
    loop_depth: int

    def increment(self) -> "BudgetState":
        return BudgetState(
            calls_used=self.calls_used + 1,
            wall_clock_start=self.wall_clock_start,
            loop_depth=self.loop_depth,
        )

    def descend(self) -> "BudgetState":
        return BudgetState(
            calls_used=self.calls_used,
            wall_clock_start=self.wall_clock_start,
            loop_depth=self.loop_depth + 1,
        )
