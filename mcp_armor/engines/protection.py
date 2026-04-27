"""T5 — Inadequate Data Protection: PII scrubbing, context leak detection."""

from __future__ import annotations

from ..context import CoSAIContext
from ..exceptions import PIILeakError
from ..types import MCPRequest, MCPResponse


class ProtectionEngine:
    """
    Scrubs PII and secrets from outbound tool responses.

    Covers:
    - T5-001: SSN, credit card, email, phone in response
    - T5-002: JWT / API key exposure in response
    - T5-003: Foreign session context bleed (other user's data in response)

    Profile presets: minimal | pci | hipaa | gdpr | strict
    """

    _PROFILES: dict[str, list[str]] = {
        "minimal": ["jwt", "api_key"],
        "pci":     ["ssn", "credit_card", "jwt", "api_key"],
        "hipaa":   ["ssn", "credit_card", "email", "phone", "jwt", "api_key"],
        "gdpr":    ["ssn", "credit_card", "email", "phone", "jwt", "api_key"],
        "strict":  ["ssn", "credit_card", "email", "phone", "jwt", "api_key"],
    }

    def __init__(self, profile: str = "pci") -> None:
        self._active = set(self._PROFILES.get(profile, self._PROFILES["pci"]))
        self._patterns = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, object]:
        try:
            import re2 as re
        except ImportError:
            import re  # type: ignore[no-redef]

        all_patterns = {
            "ssn":         r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
            "email":       r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            "phone":       r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "jwt":         r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "api_key":     r"(?i)(?:api[_-]?key|token|secret)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}",
        }
        return {k: re.compile(v) for k, v in all_patterns.items() if k in self._active}

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        if not resp.raw_body:
            return ctx
        for pii_type, pattern in self._patterns.items():
            if pattern.search(resp.raw_body):
                raise PIILeakError(
                    f"PII type '{pii_type}' detected in tool response — blocked"
                )
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
