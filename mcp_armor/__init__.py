"""mcp-armor — server-side protection middleware for MCP servers (CoSAI T1–T12)."""

from .context import CoSAIContext, get_context, set_context
from .exceptions import (
    AuditChainError,
    AuthenticationError,
    AuthorizationError,
    CoSAIException,
    InjectionDetectedError,
    IntegrityError,
    NetworkBindingError,
    PIILeakError,
    ResourceExceededError,
    SessionError,
    SupplyChainError,
    TrustBoundaryViolation,
    ValidationError,
)
from .guard import CoSAIGuard
from .types import Finding, MCPRequest, MCPResponse, Severity, ThreatCategory

__all__ = [
    "CoSAIGuard",
    "CoSAIContext",
    "get_context",
    "set_context",
    "Finding",
    "MCPRequest",
    "MCPResponse",
    "Severity",
    "ThreatCategory",
    # Exceptions
    "CoSAIException",
    "AuthenticationError",
    "AuthorizationError",
    "ValidationError",
    "InjectionDetectedError",
    "PIILeakError",
    "IntegrityError",
    "SessionError",
    "NetworkBindingError",
    "TrustBoundaryViolation",
    "ResourceExceededError",
    "SupplyChainError",
    "AuditChainError",
]
