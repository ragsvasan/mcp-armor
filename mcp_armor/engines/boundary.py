"""T4 — Data/Control Boundary: tool poisoning detection, response injection scan."""

from __future__ import annotations

from typing import Any

from ..context import CoSAIContext
from ..exceptions import InjectionDetectedError
from ..types import Finding, MCPRequest, MCPResponse, Severity, ThreatCategory


# ---------------------------------------------------------------------------
# Injection pattern library
# ---------------------------------------------------------------------------

# Core patterns (tool definition poisoning + response injection)
_CORE_PATTERNS: tuple[str, ...] = (
    r"(?i)ignore\s+(previous|all|above|prior)\s+instructions?",
    r"(?i)new\s+system\s+prompt",
    r"(?i)you\s+are\s+now\s+(a\s+)?(\w+\s+)?assistant",
    r"(?i)disregard\s+(your|all|previous)",
    r"(?i)jailbreak",
    r"(?i)developer\s+mode",
    r"(?i)DAN\s+mode",
    r"(?i)prompt\s+injection",
    r"(?i)<\|im_start\|>",
    r"(?i)<\|system\|>",
    r"(?i)\[INST\]",
    r"(?i)###\s*instruction",
    r"(?i)act\s+as\s+(if\s+you\s+are|a)\s+\w+",
    r"(?i)forget\s+(everything|all|your)\s+(you\s+know|instructions?|training)",
    r"<!--.*?(inject|override|system).*?-->",
    r"(?i)override\s+(safety|content|system)\s+(filter|policy|prompt)",
    r"(?i)bypass\s+(restrictions?|safety|filter)",
    r"(?i)do\s+anything\s+now",
)

# OWASP LLM Top 10 A01 prompt injection patterns — applied to tool call arguments
# These cover the most common real-world prompt injection vectors seen in wild (2024-2025).
_OWASP_CALL_ARG_PATTERNS: tuple[str, ...] = (
    r"(?i)ignore\s+previous\s+instructions?",   # OWASP LLM01-A01
    r"(?i)ignore\s+all\s+previous\b",           # OWASP LLM01-A02 (broader than A01)
    r"(?i)disregard\s+your\s+instructions?",    # OWASP LLM01-A03
    r"(?i)you\s+are\s+now\b",                   # OWASP LLM01-A04 (role override preamble)
    r"(?i)new\s+instructions?:",                # OWASP LLM01-A05
    r"(?i)system\s+prompt:",                    # OWASP LLM01-A06
)

_ALL_PATTERNS: tuple[str, ...] = _CORE_PATTERNS + _OWASP_CALL_ARG_PATTERNS


class BoundaryEngine:
    """
    Scans tool call arguments and tool responses for prompt injection.

    Covers:
    - T4-001: Injection patterns in tool call ARGUMENTS (user-supplied text → LLM context)
    - T4-002: Injection patterns in tool call RESPONSE bodies (indirect injection)

    The call-argument scan is the primary defence against OWASP LLM Top 10 A01
    (prompt injection via user-controlled input passed through tool parameters).

    scan_call_args (default: True) can be disabled via cosai.yaml for tools whose
    arguments are expected to contain instruction-like natural language (e.g. AI
    writing assistants).  Disabling must be an explicit, documented exception.
    """

    def __init__(self, scan_call_args: bool = True) -> None:
        self._scan_call_args = scan_call_args
        self._compiled = self._compile_patterns()

    def _compile_patterns(self) -> list[Any]:
        try:
            import re2 as re
        except ImportError:
            import re  # type: ignore[no-redef]
        return [re.compile(p) for p in _ALL_PATTERNS]

    def _scan(self, text: str) -> str | None:
        """Return the matched pattern string, or None."""
        for pattern in self._compiled:
            if pattern.search(text):
                return pattern.pattern
        return None

    def _scan_values(self, obj: Any) -> str | None:
        """
        Recursively find and scan all string values in a dict/list/scalar.

        Returns the first matched pattern string, or None.
        Only string leaf values are tested; structural keys are not scanned
        (to avoid false positives on field names like 'instructions').
        """
        if isinstance(obj, str):
            return self._scan(obj)
        if isinstance(obj, dict):
            for v in obj.values():
                matched = self._scan_values(v)
                if matched:
                    return matched
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                matched = self._scan_values(item)
                if matched:
                    return matched
        return None

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        if req.method != "tools/call":
            return ctx

        # Always scan the tool name field — defense-in-depth against injection
        # embedded in the tool name string (SupplyChainEngine is the primary gate,
        # but boundary scanning is consistent across all string params).
        tool_name = req.params.get("name", "")
        if isinstance(tool_name, str) and tool_name:
            matched = self._scan(tool_name)
            if matched:
                raise InjectionDetectedError(
                    f"Prompt injection pattern detected in tool name "
                    f"(pattern: {matched!r}) (T4-001)"
                )

        if self._scan_call_args:
            args = req.params.get("arguments", {})
            # Recursive scan of all string values — never log the matched value
            matched = self._scan_values(args)
            if matched:
                raise InjectionDetectedError(
                    f"Prompt injection pattern detected in tool call arguments "
                    f"(pattern: {matched!r}) (T4-001)"
                )
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        if resp.raw_body:
            matched = self._scan(resp.raw_body)
            if matched:
                finding = Finding(
                    threat=ThreatCategory.T4,
                    severity=Severity.HIGH,
                    code="T4-002",
                    message=f"Injection pattern in tool response (pattern: {matched!r})",
                    location="response.body",
                    remediation="Sanitize tool responses before feeding to LLM context",
                )
                ctx = ctx.with_finding(finding)
                raise InjectionDetectedError(
                    f"Injection pattern in tool response (pattern: {matched!r}) (T4-002)",
                    finding=finding,
                )
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
