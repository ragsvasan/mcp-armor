"""Exception hierarchy for mcp-armor — all fail-closed, all map to JSON-RPC error codes."""

from __future__ import annotations

from .types import Finding, ThreatCategory


class CoSAIException(Exception):
    """Base for all mcp-armor exceptions. Carries a Finding for the audit log."""

    threat: ThreatCategory
    json_rpc_code: int

    def __init__(self, message: str, finding: Finding | None = None) -> None:
        super().__init__(message)
        self.finding = finding


# Layer 1 — Transport / Session


class AuthenticationError(CoSAIException):
    """T1: Missing, invalid, or replayed authentication credential."""

    threat = ThreatCategory.T1
    json_rpc_code = -32001


class SessionError(CoSAIException):
    """T7: Session fixation, cross-transport replay, or binding failure."""

    threat = ThreatCategory.T7
    json_rpc_code = -32006


class NetworkBindingError(CoSAIException):
    """T8: Server bound to 0.0.0.0 or exposes RFC1918 surface. Startup-only."""

    threat = ThreatCategory.T8
    json_rpc_code = -32008


class SupplyChainError(CoSAIException):
    """T11: Tool not on allowlist or registry signature invalid. Startup-only."""

    threat = ThreatCategory.T11
    json_rpc_code = -32011


# Layer 2 — Tool Dispatch


class AuthorizationError(CoSAIException):
    """T2: Caller lacks required scope for this tool (confused deputy, RBAC)."""

    threat = ThreatCategory.T2
    json_rpc_code = -32002


class ValidationError(CoSAIException):
    """T3: Input fails JSON schema, injection pattern, or size limit."""

    threat = ThreatCategory.T3
    json_rpc_code = -32602  # JSON-RPC standard invalid params


class InjectionDetectedError(CoSAIException):
    """T4: Prompt injection or tool poisoning pattern detected."""

    threat = ThreatCategory.T4
    json_rpc_code = -32003


class IntegrityError(CoSAIException):
    """T6: Tool manifest changed mid-session (rug pull) or signature invalid."""

    threat = ThreatCategory.T6
    json_rpc_code = -32005


class ResourceExceededError(CoSAIException):
    """T10: Budget, rate limit, loop depth, or wall-clock limit exceeded."""

    threat = ThreatCategory.T10
    json_rpc_code = -32010  # maps to HTTP 429


# Layer 3 — Response / Re-Feed


class PIILeakError(CoSAIException):
    """T5: PII or secret detected in outbound tool response."""

    threat = ThreatCategory.T5
    json_rpc_code = -32004


class TrustBoundaryViolation(CoSAIException):
    """T9: LLM output contains injection patterns unsafe to re-feed."""

    threat = ThreatCategory.T9
    json_rpc_code = -32007


# Cross-Cutting


class AuditChainError(CoSAIException):
    """T12: Audit log chain broken — tampering detected or write failure."""

    threat = ThreatCategory.T12
    json_rpc_code = -32009


# JSON-RPC wire format helpers

_HTTP_STATUS: dict[int, int] = {
    -32001: 401,
    -32002: 403,
    -32003: 400,
    -32004: 500,
    -32005: 500,
    -32006: 401,
    -32007: 500,
    -32008: 500,
    -32009: 500,
    -32010: 429,
    -32011: 500,
    -32602: 400,
}


def to_jsonrpc_error(exc: CoSAIException) -> dict:
    return {
        "code": exc.json_rpc_code,
        "message": str(exc),
    }


def to_http_status(exc: CoSAIException) -> int:
    return _HTTP_STATUS.get(exc.json_rpc_code, 500)
