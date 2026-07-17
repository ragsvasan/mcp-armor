"""Shared types for mcp-armor — frozen dataclasses only, no mutable containers."""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any

# Unicode bidirectional override / embedding / isolate formatting characters.
# Stripped before injection and PII scanning so that bidi chars inserted between
# letters (e.g. ig[U+202E]nore) cannot split keywords and evade regex patterns.
# U+202A–U+202E: LRE, RLE, PDF, LRO, RLO
# U+2066–U+2069: LRI, RLI, FSI, PDI
BIDI_CHARS_RE = re.compile("[‪-‮⁦-⁩]")


class Severity(str, Enum):  # noqa: UP042 — (str, Enum) kept for wire/format compat, not StrEnum
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):  # noqa: UP042 — (str, Enum) kept for wire/format compat, not StrEnum
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
    code: str  # e.g. "T1-001"
    message: str  # human-readable, no PII
    location: str  # where in the request/response
    remediation: str


# F2 fix: request-phase engines previously gated on `method == "tools/call"`
# only, leaving resources/read, resources/subscribe and prompts/get — all
# first-class MCP methods that resolve URIs / templated content — entirely
# unauthorized, unvalidated and SSRF-unchecked. These methods carry attacker-
# influenced content that must run the same scanning chain as tools/call.
CONTENT_BEARING_METHODS: frozenset[str] = frozenset(
    {
        "tools/call",
        "resources/read",
        "resources/subscribe",
        "prompts/get",
    }
)


# T7 — MCP §3.2 lifecycle handshake phases. Tracked per session in
# CoSAIContext and enforced by SessionEngine ONLY when
# T7.require_initialized_handshake is enabled (opt-in; default off).
#   ACTIVE  — full method set permitted (the default: a session this worker
#             never saw `initialize` for is treated as already-initialized so
#             enforcement is scoped to sessions whose handshake this worker is
#             actually tracking — consistent with the F4/F7 single-worker model).
#   PENDING — `initialize` was processed but `notifications/initialized` has not
#             yet arrived; only the handshake methods below are permitted.
HANDSHAKE_PENDING = "pending"
HANDSHAKE_ACTIVE = "active"

# MCP §3.2: before the client sends `notifications/initialized`, the only
# requests permitted are the initialize handshake itself and pings. Everything
# else (tools/list, tools/call, resources/*, prompts/*, …) is rejected while the
# session is PENDING.
HANDSHAKE_ALLOWED_METHODS: frozenset[str] = frozenset(
    {"initialize", "notifications/initialized", "ping"}
)


def scannable_strings(req: MCPRequest) -> dict[str, Any]:
    """
    Return the attacker-influenced fields of a content-bearing request that
    must be scanned by validation/boundary/SSRF engines.

    Normalises the per-method parameter shape so every engine scans the same
    surface regardless of method:
      - tools/call:          {name, arguments}
      - resources/read:      {uri}
      - resources/subscribe: {uri}
      - prompts/get:         {name, arguments}
    Unknown / non-content methods return {} (engines early-return).
    """
    if req.method not in CONTENT_BEARING_METHODS:
        return {}
    p = req.params
    out: dict[str, Any] = {}
    name = p.get("name")
    if isinstance(name, str) and name:
        out["name"] = name
    args = p.get("arguments")
    if args is not None:
        out["arguments"] = args
    uri = p.get("uri")
    if uri is not None:
        out["uri"] = uri
    return out


@dataclass(frozen=True)
class MCPRequest:
    method: str  # e.g. "tools/call"
    params: MappingProxyType[str, Any]
    session_id: str
    raw_headers: MappingProxyType[str, str]
    # URL query parameters — used by SessionEngine to detect session_id in URL (T7-002)
    url_query_params: MappingProxyType[str, str] = field(
        default_factory=lambda: MappingProxyType({})
    )
    # Transport type — used by SessionEngine to detect cross-transport replay (T7-003)
    transport: str = "http"

    @classmethod
    def from_dict(
        cls,
        d: dict[str, Any],
        session_id: str,
        headers: dict[str, str],
        url_query_params: dict[str, str] | None = None,
        transport: str = "http",
    ) -> MCPRequest:
        # A JSON-RPC request MAY carry positional (array) or scalar `params`, but
        # mcp-armor's engines only inspect object params. Coercing a non-object to
        # {} would make the guard scan an EMPTY params while the raw array/scalar
        # is still forwarded to the backend verbatim (the ASGI adapter replays
        # raw_body; wrap_dispatcher passes the original payload) — a scan/forward
        # asymmetry that lets injection payloads in by-position params reach an
        # upstream doing positional binding, unscanned. Reject non-object params:
        # fail CLOSED so the guard never forwards a representation it did not scan.
        params_obj = d.get("params", {})
        if not isinstance(params_obj, dict):
            from .exceptions import ValidationError

            raise ValidationError(
                "JSON-RPC params must be a JSON object; positional (array) or "
                "scalar params are not supported by the mcp-armor guard"
            )
        return cls(
            method=str(d.get("method", "")),
            params=MappingProxyType(dict(params_obj)),
            session_id=session_id,
            raw_headers=MappingProxyType(headers),
            url_query_params=MappingProxyType(url_query_params or {}),
            transport=transport,
        )


def normalize_for_scan(text: str) -> str:
    """
    Decode HTML entities then NFKC-normalize so injection/PII detectors see the
    text the LLM will effectively see, not an escaped/encoded representation.

    Defends both directions of the F1 bypass class:
    - payloads whose signature chars (``<`` ``>`` ``&``) were HTML-escaped
      somewhere upstream (the original detection-bypass);
    - payloads that arrive deliberately entity-encoded (``&lt;|im_start|&gt;``)
      to slip past literal-character regexes (the inverse bypass).
    """
    # html.unescape handles named and numeric entities, including the
    # double-escaped forms produced by escaping already-escaped text.
    prev = text
    for _ in range(3):  # bounded fixpoint — collapse double/triple encoding
        nxt = html.unescape(prev)
        if nxt == prev:
            break
        prev = nxt
    # Strip bidi formatting chars after entity decode so that entity-encoded
    # bidi chars (e.g. &#x202E;) are also removed before pattern matching.
    prev = BIDI_CHARS_RE.sub("", prev)
    return unicodedata.normalize("NFKC", prev)


@dataclass(frozen=True)
class MCPResponse:
    result: MappingProxyType[str, Any] | None
    error: MappingProxyType[str, Any] | None
    raw_body: str  # HTML-escaped — safe for downstream rendering
    # Raw, pre-escape, entity-decoded text the detectors MUST scan (F1 fix).
    # Optional in the constructor: when omitted it is derived from raw_body by
    # entity-decoding, so legacy callers and tests that pass an already-raw
    # raw_body still get correct detection. The canonical builders
    # (from_dict / from_text) populate it explicitly from the pre-escape source.
    scan_body: str = ""

    def __post_init__(self) -> None:
        if not self.scan_body and self.raw_body:
            # Derive a scannable view: decode any HTML entities present in
            # raw_body (covers the F1 escape) and NFKC-normalize. Fail-safe:
            # if raw_body was never escaped this is an identity transform.
            object.__setattr__(self, "scan_body", normalize_for_scan(self.raw_body))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MCPResponse:
        # H1 (response scan/forward asymmetry): the detectors must inspect the
        # FULL body that is forwarded to the client. The 64 KB cap is applied
        # ONLY to raw_body (the escaped, rendered/audited view) — NOT to
        # scan_body. A PII/secret payload positioned past 64 KB, or any bytes the
        # old truncation dropped, were previously egress'd unscanned.
        raw = str(d)
        # Guard result/error: only wrap true mappings. A non-object result (e.g.
        # a list or scalar) would make MappingProxyType(...) raise TypeError.
        result = d.get("result")
        error = d.get("error")
        return cls(
            result=MappingProxyType(result) if isinstance(result, dict) else None,
            error=MappingProxyType(error) if isinstance(error, dict) else None,
            raw_body=html.escape(raw[:65536], quote=True),  # cap ONLY for rendering
            scan_body=normalize_for_scan(raw),  # full body — what detectors must see (F1/H1)
        )

    @classmethod
    def from_text(cls, text: str) -> MCPResponse:
        """Build a response from a raw text payload (decorator / per-tool path).

        Keeps an unescaped, entity-decoded copy for detection so the F1
        HTML-escape bypass cannot recur on the @guard.protect()/FastMCP
        decorator paths either.
        """
        # H1 parity with from_dict: cap ONLY the rendered raw_body; scan the FULL
        # text so a PII/secret positioned past 64 KB in a tool result is not
        # returned unscanned on the @guard.protect / FastMCP decorator path.
        return cls(
            result=None,
            error=None,
            raw_body=html.escape(text[:65536], quote=True),
            scan_body=normalize_for_scan(text),
        )


@dataclass(frozen=True)
class BudgetState:
    calls_used: int
    wall_clock_start: float  # time.monotonic() at session start
    loop_depth: int

    def increment(self) -> BudgetState:
        return BudgetState(
            calls_used=self.calls_used + 1,
            wall_clock_start=self.wall_clock_start,
            loop_depth=self.loop_depth,
        )

    def descend(self) -> BudgetState:
        return BudgetState(
            calls_used=self.calls_used,
            wall_clock_start=self.wall_clock_start,
            loop_depth=self.loop_depth + 1,
        )
