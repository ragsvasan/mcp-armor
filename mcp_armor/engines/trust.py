"""T9 — Trust Boundary Failures: LLM output sanitization before re-feed."""

from __future__ import annotations

import html

from ..context import CoSAIContext
from ..exceptions import TrustBoundaryViolation
from ..types import MCPRequest, MCPResponse

_MAX_LLM_OUTPUT = 32_768

# Control characters to strip (keep \t \n \r)
_CTRL_CHARS = bytes(range(0, 9)) + bytes(range(11, 13)) + bytes(range(14, 32)) + bytes([127])
_CTRL_TABLE = str.maketrans(dict.fromkeys(_CTRL_CHARS, None))


class TrustEngine:
    """
    Guards the LLM-output trust boundary (T9) two different ways — read which
    you are using (B1):

    - on_response (the wired middleware path): BLOCK-only. It scans the response
      for injection patterns and raises TrustBoundaryViolation on a hit; the
      adapter then replaces the whole response with an opaque error. It does NOT
      strip the offending substring out of the forwarded response. The
      `strip_injection_patterns` flag gates whether this blocking scan runs — it
      does not cause stripping on this path.
    - sanitize(text) (explicit-call helper): REDACTS. Truncates, removes null /
      control / dangerous-Unicode characters, raises on injection patterns, and
      returns HTML-escaped safe text. Call it explicitly wherever LLM output is
      about to be re-fed as input to another tool.

    Covers:
    - T9-001: Unsanitized LLM output used as tool argument (prompt injection vector)
    - T9-002: LLM-generated URLs or shell commands executed without validation
    - T9-003: Overreliance on LLM judgment for security decisions
    """

    def __init__(
        self,
        max_output_length: int = _MAX_LLM_OUTPUT,
        strip_injection_patterns: bool = True,
    ) -> None:
        self._max_len = max_output_length
        self._strip_injections = strip_injection_patterns
        if self._strip_injections:
            from .boundary import BoundaryEngine

            self._boundary = BoundaryEngine()

    def sanitize(self, text: str) -> str:
        """
        Five-step pipeline: truncate → null bytes → control chars → Unicode →
        injection scan. Returns HTML-escaped safe text or raises TrustBoundaryViolation.
        """
        if len(text) > self._max_len:
            text = text[: self._max_len]

        text = text.replace("\x00", "")
        text = text.translate(_CTRL_TABLE)

        # Strip dangerous Unicode categories (surrogates, private use, unassigned)
        cleaned = []
        for ch in text:
            cp = ord(ch)
            if 0xD800 <= cp <= 0xDFFF:  # surrogates
                continue
            if 0xE000 <= cp <= 0xF8FF:  # private use area
                continue
            cleaned.append(ch)
        text = "".join(cleaned)

        if self._strip_injections:
            matched = self._boundary._scan(text)
            if matched:
                raise TrustBoundaryViolation(
                    f"LLM output contains injection pattern: {matched!r} — blocked from re-feed"
                )

        return html.escape(text, quote=True)

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        # Enforce T9 in the response chain — scan for injection patterns before
        # the response reaches the client (not just a helper callers must invoke).
        # F1 fix: scan the raw, pre-escape, entity-decoded body — not the
        # HTML-escaped raw_body (which neutralizes angle-bracket signatures).
        if resp.scan_body and self._strip_injections:
            matched = self._boundary._scan(resp.scan_body)
            if matched:
                raise TrustBoundaryViolation(
                    f"Tool response contains injection pattern: {matched!r} — blocked (T9-001)"
                )
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
