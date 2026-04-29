"""Shared test fixtures for mcp-armor."""

from __future__ import annotations

import time
import uuid
from types import MappingProxyType

import pytest

from mcp_armor.context import CoSAIContext
from mcp_armor.types import BudgetState, MCPRequest, MCPResponse


def make_ctx(session_id: str | None = None, transport: str = "http") -> CoSAIContext:
    return CoSAIContext.new(session_id or str(uuid.uuid4()), transport=transport)


def make_request(
    method: str = "tools/call",
    params: dict | None = None,
    headers: dict | None = None,
    session_id: str | None = None,
    transport: str = "http",
) -> MCPRequest:
    return MCPRequest(
        method=method,
        params=MappingProxyType(params or {}),
        session_id=session_id or str(uuid.uuid4()),
        raw_headers=MappingProxyType(headers or {}),
        transport=transport,
    )


def make_response(body: str = "") -> MCPResponse:
    return MCPResponse(result=None, error=None, raw_body=body)
