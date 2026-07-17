"""T4 — Data/Control Boundary: tool poisoning detection, response injection scan."""

from __future__ import annotations

import base64
import html
import itertools
import re
import unicodedata
from typing import Any, cast

from ..context import CoSAIContext
from ..exceptions import InjectionDetectedError
from ..types import (
    BIDI_CHARS_RE,
    Finding,
    MCPRequest,
    MCPResponse,
    Severity,
    ThreatCategory,
    scannable_strings,
)

# Per-regex-call length bound used ONLY when re2 (linear-time) is unavailable —
# it bounds stdlib `re`'s worst-case time per call. LOW fix: this used to be
# applied as a hard truncation of the whole string, which meant a payload
# positioned past this offset was never scanned even though the full body is
# what gets forwarded — the same "scan what you forward" gap as the response
# scan/forward asymmetry. It is now used two ways instead: (1) when re2 IS
# loaded, _scan() does not cap length at all — re2 is linear-time regardless
# of input size, so capping bought nothing but a blind spot; (2) when re2 is
# unavailable, _scan_windows() slides this-sized, overlapping windows across
# the FULL text so every byte is still scanned, with each regex call still
# bounded to this many chars.
_MAX_SCAN_LEN = 8_192

# Overlap between consecutive scan windows (see _scan_windows) — generous vs.
# the longest injection pattern's maximum matchable span (well under 100 chars)
# so a pattern straddling a window boundary is always fully contained in the
# next window and cannot be split across the seam.
_SCAN_WINDOW_OVERLAP = 1_024

# ---------------------------------------------------------------------------
# Normalization pipeline (Fix 7)
# ---------------------------------------------------------------------------

# Zero-width and invisible characters that are used to split keywords
_ZERO_WIDTH_CHARS = (
    "​"  # zero-width space
    "‌"  # zero-width non-joiner
    "‍"  # zero-width joiner
    "﻿"  # zero-width no-break space (BOM)
    "­"  # soft hyphen
)
_ZERO_WIDTH_RE = re.compile(f"[{re.escape(_ZERO_WIDTH_CHARS)}]")

# Soft-hyphen and regular hyphen used to split words ("ig-nore pre-vious")
# Match hyphens that appear between word characters (not at word boundaries)
_SPLIT_HYPHEN_RE = re.compile(r"(?<=[a-zA-Z])-(?=[a-zA-Z])")

# Collapse multiple whitespace runs to a single space
_WHITESPACE_RE = re.compile(r"\s+")

# Base64 token detector: ≥16 chars using the standard or URL-safe Base64 alphabet,
# optionally padded, followed by a non-base64 char or end of string.
_BASE64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{16,}(?![A-Za-z0-9+/=_-])")


def _normalize_for_injection_scan(text: str) -> str:
    """
    Normalize text before applying injection regex patterns.

    Pipeline:
    1. HTML entity decode (bounded 3-pass fixpoint) — catches entity-encoded
       payloads like ``&lt;|im_start|&gt;`` on the tool call args path where
       normalize_for_scan() is NOT called upstream.
    2. Strip Unicode bidi override/embedding/isolate formatting characters
       (U+202A–U+202E, U+2066–U+2069) — these survive NFKC and can interleave
       letters to break keyword regexes (e.g. ig[RLO]nore).
    3. Strip zero-width characters (used to split keywords invisibly)
    4. Remove intra-word soft hyphens / hyphens (split-word bypass)
    5. Collapse whitespace runs to single spaces
    6. NFKC normalization (Unicode lookalikes)
    """
    # Step 1: bounded HTML entity decode — same 3-pass fixpoint loop as
    # normalize_for_scan(); additional bidi/zero-width/hyphen steps follow.
    for _ in range(3):
        decoded = html.unescape(text)
        if decoded == text:
            break
        text = decoded
    # Step 2: strip bidi formatting characters
    text = BIDI_CHARS_RE.sub("", text)
    # Step 3: strip zero-width chars
    text = _ZERO_WIDTH_RE.sub("", text)
    # Step 4: remove intra-word hyphens ("ig-nore" → "ignore")
    text = _SPLIT_HYPHEN_RE.sub("", text)
    # Step 5: collapse whitespace
    text = _WHITESPACE_RE.sub(" ", text).strip()
    # Step 6: NFKC
    return unicodedata.normalize("NFKC", text)


_BASE64_MAX_MATCHES = 8  # cap: at most 8 tokens decoded per call (Fix 4 DoS guard)
_BASE64_MAX_DECODED_CHARS = 512  # total decoded surface budget per call


def _try_decode_base64_tokens(text: str) -> str | None:
    """
    If text contains any Base64-looking token (≥16 chars, valid B64 alphabet,
    decodable to valid UTF-8), return the decoded text to be appended to the
    scan surface.  Returns None if no decodable token is found.

    Fix 4 (CPU DoS): text MUST already be truncated to _MAX_SCAN_LEN by the
    caller. We additionally cap to _BASE64_MAX_MATCHES matches and
    _BASE64_MAX_DECODED_CHARS of decoded surface to bound decode work.
    """
    decoded_parts: list[str] = []
    budget = _BASE64_MAX_DECODED_CHARS
    for match in itertools.islice(_BASE64_TOKEN_RE.finditer(text), _BASE64_MAX_MATCHES):
        token = match.group(0)
        # Try standard and URL-safe variants with and without padding
        for variant in (token, token.replace("-", "+").replace("_", "/")):
            padded = variant + "=" * ((-len(variant)) % 4)
            try:
                decoded_bytes = base64.b64decode(padded, validate=False)
                decoded_str = decoded_bytes.decode("utf-8")
                if len(decoded_str) <= budget:
                    decoded_parts.append(decoded_str)
                    budget -= len(decoded_str)
                else:
                    # Append only up to remaining budget
                    decoded_parts.append(decoded_str[:budget])
                    budget = 0
                break  # found a decodable form
            except Exception:  # noqa: S112 — non-decodable candidate; try the next form (hot path)
                continue
        if budget <= 0:
            break  # decoded surface budget exhausted
    return " ".join(decoded_parts) if decoded_parts else None


def _scan_windows(
    text: str, window: int = _MAX_SCAN_LEN, overlap: int = _SCAN_WINDOW_OVERLAP
) -> list[str]:
    """
    Split `text` into overlapping windows of at most `window` chars each, with
    `overlap` chars shared between consecutive windows.

    Used only on the re2-unavailable fallback path: bounds each individual
    regex call to `window` chars (the historical ReDoS guard for stdlib `re`)
    while still covering every byte of `text` — a payload placed past a fixed
    offset can no longer evade detection simply by position. The overlap
    guarantees a pattern straddling a window boundary is fully contained
    within the following window.
    """
    if len(text) <= window:
        return [text]
    stride = window - overlap
    windows: list[str] = []
    n = len(text)
    start = 0
    while True:
        end = min(start + window, n)
        windows.append(text[start:end])
        if end >= n:
            break
        start += stride
    return windows


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
    r"(?i)ignore\s+previous\s+instructions?",  # OWASP LLM01-A01
    r"(?i)ignore\s+all\s+previous\b",  # OWASP LLM01-A02 (broader than A01)
    r"(?i)disregard\s+your\s+instructions?",  # OWASP LLM01-A03
    r"(?i)you\s+are\s+now\b",  # OWASP LLM01-A04 (role override preamble)
    r"(?i)new\s+instructions?:",  # OWASP LLM01-A05
    r"(?i)system\s+prompt:",  # OWASP LLM01-A06
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

    def __init__(self, scan_call_args: bool = True, scan_responses: bool = True) -> None:
        self._scan_call_args = scan_call_args
        self._scan_responses = scan_responses
        # Set for real by _compile_patterns() below; declared here so the
        # attribute always exists regardless of which branch it takes.
        self._using_re2 = False
        self._compiled = self._compile_patterns()

    def _compile_patterns(self) -> list[Any]:
        try:
            import re2 as re

            self._using_re2 = True
        except ImportError:
            import re

            self._using_re2 = False
        return [re.compile(p) for p in _ALL_PATTERNS]

    def _scan(self, text: str) -> str | None:
        """
        Return the matched pattern string, or None.

        Scans:
        1. The original text (catches obvious patterns)
        2. A normalized copy (catches split-word, zero-width, hyphenated bypasses)
        3. Any Base64-decoded content found in the text (catches encoded payloads)

        LOW fix (boundary.py + trust.py, which delegates here): the match step
        used to truncate every candidate to _MAX_SCAN_LEN before matching, so a
        payload positioned past that fixed offset could never be seen even
        though the full body is what gets forwarded. Now: when re2 is loaded
        the match step runs over the FULL text with no length cap at all (re2
        is linear-time, so capping it bought nothing but a blind spot). When
        re2 is unavailable, each regex call is still bounded to _MAX_SCAN_LEN
        chars, but applied across overlapping windows spanning the entire text
        (_scan_windows) instead of just the first window.
        """
        # Base64 detection surface is unchanged by this fix: it stays bounded
        # to the first _MAX_SCAN_LEN chars of the (possibly normalized) text,
        # per the existing Fix 4 CPU-DoS guard in _try_decode_base64_tokens.
        b64_source = text[:_MAX_SCAN_LEN] if len(text) > _MAX_SCAN_LEN else text
        decoded = _try_decode_base64_tokens(b64_source)
        decoded_norm = _normalize_for_injection_scan(decoded) if decoded else None

        normalized = _normalize_for_injection_scan(text)

        sources = [text]
        if normalized != text:
            sources.append(normalized)
        if decoded_norm:
            sources.append(decoded_norm)

        if self._using_re2:
            # Linear-time regardless of input size — no length cap needed.
            for source in sources:
                for pattern in self._compiled:
                    if pattern.search(source):
                        return cast(str, pattern.pattern)
            return None

        # No re2: bound each regex call to _MAX_SCAN_LEN chars but slide
        # across the full text in overlapping windows so a payload past the
        # old fixed offset can no longer evade detection.
        for source in sources:
            for window in _scan_windows(source):
                for pattern in self._compiled:
                    if pattern.search(window):
                        return cast(str, pattern.pattern)
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
        # F2 fix: scan every content-bearing method. prompts/get.arguments and
        # resources/read.uri are attacker-influenced text fed to the LLM exactly
        # like tools/call arguments — previously skipped entirely.
        fields = scannable_strings(req)
        if not fields:
            return ctx

        # Always scan the tool/resource name field — defense-in-depth against
        # injection embedded in the name string (SupplyChainEngine is the
        # primary gate, but boundary scanning is consistent across all params).
        tool_name = fields.get("name", "")
        if isinstance(tool_name, str) and tool_name:
            matched = self._scan(tool_name)
            if matched:
                raise InjectionDetectedError(
                    f"Prompt injection pattern detected in tool name "
                    f"(pattern: {matched!r}) (T4-001)"
                )

        # Scan the resources/* uri the same way (F2).
        uri = fields.get("uri")
        if isinstance(uri, str) and uri:
            matched = self._scan(uri)
            if matched:
                raise InjectionDetectedError(
                    f"Prompt injection pattern detected in resource uri "
                    f"(pattern: {matched!r}) (T4-001)"
                )

        if self._scan_call_args and "arguments" in fields:
            args = fields["arguments"]
            # Recursive scan of all string values — never log the matched value
            matched = self._scan_values(args)
            if matched:
                raise InjectionDetectedError(
                    f"Prompt injection pattern detected in tool call arguments "
                    f"(pattern: {matched!r}) (T4-001)"
                )
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        if not self._scan_responses:
            return ctx

        # T4-003: scan tool descriptions from tools/list manifests — tool definition
        # poisoning via description is the primary indirect-injection attack surface.
        # resp.result is the structured (unescaped) dict; raw_body is HTML-escaped.
        if resp.result is not None and "tools" in resp.result:
            tools = resp.result.get("tools") or []
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                desc = tool.get("description", "")
                if isinstance(desc, str) and desc:
                    matched = self._scan(desc)
                    if matched:
                        tool_name = tool.get("name", "?")
                        finding = Finding(
                            threat=ThreatCategory.T4,
                            severity=Severity.HIGH,
                            code="T4-003",
                            message=(
                                f"Injection pattern in tool description "
                                f"(tool: {tool_name!r}, pattern: {matched!r})"
                            ),
                            location="tools/list.tools[].description",
                            remediation=(
                                "Sanitize tool descriptions before serving to LLM context"
                            ),
                        )
                        ctx = ctx.with_finding(finding)
                        raise InjectionDetectedError(
                            f"Injection pattern in tool description for tool "
                            f"{tool_name!r} (pattern: {matched!r}) (T4-003)",
                            finding=finding,
                        )

        # F1 fix: scan the raw, pre-escape, entity-decoded body. Scanning
        # resp.raw_body (HTML-escaped) made the <|im_start|> / <!-- --> /
        # angle-bracket signatures structurally unmatchable on tool responses.
        if resp.scan_body:
            matched = self._scan(resp.scan_body)
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
