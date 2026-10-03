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


_MAX_KWARG_DEPTH = 64
_MAX_MATERIALIZED_ITEMS = 10_000


def _str_faithful_types() -> tuple[type, ...]:
    import datetime
    import decimal
    import fractions
    import ipaddress
    import pathlib
    import uuid

    extra: tuple[type, ...] = ()
    try:
        from pydantic_core import MultiHostUrl, Url

        extra = (Url, MultiHostUrl)
        from pydantic import networks as _networks

        extra += tuple(
            t for t in (getattr(_networks, "_BaseUrl", None),
                        getattr(_networks, "_BaseMultiHostUrl", None))
            if isinstance(t, type)
        )
    except ImportError:  # pragma: no cover
        pass
    return (datetime.date, datetime.time, datetime.timedelta, datetime.tzinfo,
            decimal.Decimal, fractions.Fraction, uuid.UUID, pathlib.PurePath,
            ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network,
            ipaddress.IPv6Network, complex, *extra)


_STR_FAITHFUL_TYPES = _str_faithful_types()

# Scan-view budget: every list item AND mapping/model entry is charged once,
# so it is larger than the per-call iterator materialisation cap.
_MAX_SCAN_ENTRIES = 100_000


def materialize_iterators(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Replace top-level lazy iterators (pydantic ``Iterable[...]`` /
    generators) with bounded lists so the guard scans exactly what the tool
    then iterates. The returned kwargs are what the tool must be called with."""
    import itertools
    from collections.abc import Iterator

    out: dict[str, Any] = {}
    remaining = _MAX_MATERIALIZED_ITEMS      # per call, across all iterator args
    for key, value in kwargs.items():
        if isinstance(value, Iterator):
            try:
                items = list(itertools.islice(value, remaining + 1))
            except Exception:
                from .exceptions import ValidationError

                raise ValidationError("Tool argument cannot be scanned") from None
            remaining -= len(items)
            if remaining < 0:
                from .exceptions import ValidationError

                raise ValidationError(f"Tool argument {key!r} has too many items")
            out[key] = items
        else:
            out[key] = value
    return out


def _view_mapping(items: Any, depth: int, seen: set[int], budget: list[int]) -> dict[str, Any]:
    """Scan view of key/value pairs. Every entry is charged to the shared item
    budget (diamond-shaped graphs cannot expand unbounded) and keys that
    stringify alike (``1`` vs ``"1"``) are all kept, never overwritten."""
    out: dict[str, Any] = {}
    collisions: dict[str, int] = {}
    for k, v in items:
        budget[0] -= 1
        if budget[0] < 0:
            from .exceptions import ValidationError

            raise ValidationError("Tool argument has too many items to scan")
        base = key = str(k)
        while key in out:
            collisions[base] = n = collisions.get(base, 0) + 1
            key = f"{base}\x00{type(k).__name__}\x00{n}"
        out[key] = _scan_view(v, depth + 1, seen, budget)
    return out


def _scan_view(value: Any, depth: int, seen: set[int], budget: list[int] | None = None,
               ) -> Any:
    """Faithful plain-data view of a framework-parsed value for scanning:
    what the tool body can READ, not how it would serialise (no aliases,
    serializers, exclusions or secret masking)."""
    import dataclasses
    import enum
    import itertools
    import numbers
    import re

    if budget is None:
        budget = [_MAX_SCAN_ENTRIES]
    if depth > _MAX_KWARG_DEPTH:
        from .exceptions import ValidationError

        raise ValidationError("Tool argument nesting too deep to scan")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", errors="replace")
    get_secret = getattr(value, "get_secret_value", None)
    if callable(get_secret):                              # SecretStr / SecretBytes
        return _scan_view(get_secret(), depth + 1, seen, budget)
    if id(value) in seen:
        return "<cycle>"
    seen = seen | {id(value)}
    if isinstance(value, dict):
        return _view_mapping(value.items(), depth, seen, budget)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        # Superset of what the tool can read: fields, non-field instance
        # attributes (pydantic dataclass extra='allow', __post_init__ state)
        # and extras — a colliding name is kept under a disambiguated key.
        pairs: list[tuple[Any, Any]] = [
            (f.name, getattr(value, f.name, None)) for f in dataclasses.fields(value)]
        names = {f.name for f in dataclasses.fields(value)}
        attrs = getattr(value, "__dict__", None)
        if isinstance(attrs, dict):
            pairs += [(k, v) for k, v in attrs.items() if k not in names]
        extra = getattr(value, "__pydantic_extra__", None)
        if isinstance(extra, dict):
            pairs += list(extra.items())
        return _view_mapping(pairs, depth, seen, budget)
    model_fields = getattr(type(value), "model_fields", None)
    if isinstance(model_fields, dict):                    # pydantic BaseModel
        pairs = list(dict(getattr(value, "__dict__", {})).items())
        extra = getattr(value, "model_extra", None)
        if isinstance(extra, dict):
            pairs += list(extra.items())
        return _view_mapping(pairs, depth, seen, budget)
    from collections.abc import Iterable, Iterator, Mapping

    if isinstance(value, enum.Enum):           # incl. Flag (iterable in 3.11+)
        return _scan_view(value.value, depth + 1, seen, budget)
    if isinstance(value, re.Pattern):
        return _scan_view(value.pattern, depth + 1, seen, budget)
    if isinstance(value, _STR_FAITHFUL_TYPES):   # before Iterable: IP networks iterate
        return str(value)

    if isinstance(value, Mapping):
        return _view_mapping(value.items(), depth, seen, budget)
    if getattr(value, "ndim", None) == 0 and callable(getattr(value, "item", None)):
        return _scan_view(value.item(), depth + 1, seen, budget)   # numpy scalars
    if isinstance(value, Iterator):
        # A lazy iterator cannot be scanned without consuming what the tool
        # will read; top-level iterators are materialised by the decorator
        # wrappers (materialize_iterators) — a nested one fails closed.
        from .exceptions import ValidationError

        raise ValidationError("Tool argument contains a lazy iterator that cannot be scanned")
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        out: list[Any] = []
        for item in itertools.islice(value, budget[0] + 1):
            budget[0] -= 1
            if budget[0] < 0:
                from .exceptions import ValidationError

                raise ValidationError("Tool argument has too many items to scan")
            out.append(_scan_view(item, depth + 1, seen, budget))
        return out
    if isinstance(value, numbers.Integral):    # numpy ints etc.
        return int(value)
    if isinstance(value, numbers.Real):
        return float(value)
    if isinstance(value, _STR_FAITHFUL_TYPES):
        return str(value)
    # No faithful plain-data view: never scan a repr in its place.
    from .exceptions import ValidationError

    raise ValidationError(
        f"Tool argument of type {type(value).__name__!r} cannot be scanned"
    )


def jsonable_arguments(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Tool kwargs as plain data (dict/list/str/number/bool/None) for scanning.

    Decorator paths (@guard.protect, the FastMCP per-tool hook) see kwargs
    AFTER the framework parsed them — pydantic models, dataclasses, enums,
    secrets, bytes. The scanners only walk dict/list/str, so everything is
    converted to what the tool can actually read: model attributes (incl.
    excluded / serializer-masked fields and extras), dataclass fields, secret
    values, bytes as text. Never raises except a typed ValidationError for
    structures too deep / too large to scan or values whose attributes or
    iteration raise; the tool still receives the original kwargs.
    """
    from .exceptions import ValidationError

    budget = [_MAX_SCAN_ENTRIES]
    try:
        return _view_mapping(kwargs.items(), 0, set(), budget)
    except ValidationError:
        raise
    except Exception:
        raise ValidationError("Tool argument cannot be scanned") from None


def decoded_json_string_arguments(arguments: Any) -> dict[str, Any]:
    """Top-level string arguments holding a JSON object/array, decoded.

    The official MCP Python SDK (FastMCP ``pre_parse_json``) ``json.loads``
    such strings for non-``str`` parameters and runs the decoded value, so
    ``\\uXXXX``-escaped payloads (``;``, ``../``, ``http\\u003a//``, prompt
    injection) only exist after decoding. Every request scanner (T3, T4, T8)
    must scan these decoded values as well as the raw strings.
    """
    import json as _json

    out: dict[str, Any] = {}
    if not isinstance(arguments, dict):
        return out
    for key, value in arguments.items():
        if not isinstance(value, str):
            continue
        stripped = value.strip()
        if not stripped or stripped[0] not in "[{":
            continue
        if _bracket_depth(stripped) > _MAX_DECODE_DEPTH:
            # Never let the verdict depend on the guard's own stack depth (a
            # RecursionError here while the server's shallower stack decodes
            # fine would skip every decoded-value scan). Too deep = reject.
            from .exceptions import ValidationError

            raise ValidationError(
                f"Argument {key!r} holds JSON nested deeper than {_MAX_DECODE_DEPTH}"
            )
        try:
            decoded = _json.loads(stripped)
        except RecursionError:
            from .exceptions import ValidationError

            raise ValidationError(f"Argument {key!r} holds JSON that is too deep") from None
        except ValueError:
            continue           # not JSON — the server keeps it as a plain string
        if isinstance(decoded, (dict, list)):
            out[key] = decoded
    return out


_MAX_DECODE_DEPTH = 64


def _bracket_depth(text: str) -> int:
    """Maximum ``[``/``{`` nesting outside JSON strings — iterative, stack-free."""
    depth = best = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > best:
                best = depth
        elif ch in "]}":
            depth -= 1
    return best


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
        decoded = decoded_json_string_arguments(args)
        if decoded:
            out["decoded_arguments"] = decoded
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
    # Raw (name, value) header pairs in arrival order, duplicates preserved —
    # used by EnvelopeEngine to reject duplicated MCP routing headers that the
    # de-duplicated raw_headers mapping would hide.
    raw_header_pairs: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_dict(
        cls,
        d: dict[str, Any],
        session_id: str,
        headers: dict[str, str],
        url_query_params: dict[str, str] | None = None,
        transport: str = "http",
        header_pairs: tuple[tuple[str, str], ...] = (),
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
            raw_header_pairs=header_pairs,
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
