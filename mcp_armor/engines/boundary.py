"""T4 — Data/Control Boundary: tool poisoning detection, response injection scan."""

from __future__ import annotations

from ..context import CoSAIContext
from ..exceptions import InjectionDetectedError
from ..types import MCPRequest, MCPResponse, Severity, ThreatCategory, Finding


# Patterns ported from cosai_mcp/middleware/boundary.py (RE2-compatible)
_INJECTION_PATTERNS: tuple[str, ...] = (
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


class BoundaryEngine:
    """
    Scans tool definitions and tool responses for prompt injection.

    Covers:
    - T4-001: Injection patterns in tool name/description/inputSchema (poisoning)
    - T4-002: Injection patterns in tool call response bodies (indirect injection)

    This engine must be in the call path — black-box scanning cannot detect T4.
    """

    def __init__(self) -> None:
        self._compiled = self._compile_patterns()

    def _compile_patterns(self):
        try:
            import re2 as re
        except ImportError:
            import re  # type: ignore[no-redef]
        return [re.compile(p) for p in _INJECTION_PATTERNS]

    def _scan(self, text: str) -> str | None:
        for pattern in self._compiled:
            if pattern.search(text):
                return pattern.pattern
        return None

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        # Scan tool call arguments for injection attempts
        if req.method == "tools/call":
            args_text = str(req.params.get("arguments", ""))
            matched = self._scan(args_text)
            if matched:
                raise InjectionDetectedError(
                    f"Injection pattern detected in tool arguments: {matched!r}"
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
                    message=f"Injection pattern in tool response: {matched!r}",
                    location="response.body",
                    remediation="Sanitize tool responses before feeding to LLM context",
                )
                ctx = ctx.with_finding(finding)
                raise InjectionDetectedError(
                    f"Injection pattern in tool response: {matched!r}",
                    finding=finding,
                )
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
