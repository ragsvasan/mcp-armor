"""MCP 2026-07-28 request metadata enforcement — CoSAI v2.0 TN-04 and SD-02.

Server-side counterparts of the scanner's T07-004/005 and T01-007 probes.

:func:`validate_request_metadata` — Streamable HTTP mirrors the JSON-RPC body
into ``MCP-Protocol-Version`` / ``Mcp-Method`` / ``Mcp-Name`` / ``Mcp-Param-*``
headers so intermediaries can route without parsing. A server (or gateway) that
trusts the headers while executing the body is split-brained; the spec requires
rejecting any disagreement with HTTP 400 + ``-32020`` *before* routing,
authorization, rate limiting, caching, or execution, and ``-32022`` for
unsupported versions.

:func:`reconcile_meta` — ``_meta`` identity/role claims are self-asserted by the
caller. They must never be an authorization input: any claim that conflicts
with the authenticated principal is rejected (and should be logged as a
security-relevant failure), and role/scope claims can never expand the
principal's scopes. ``clientInfo`` is display-only and is not checked.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .exceptions import AuthorizationError, CoSAIException
from .mcp_protocol import (
    ERR_HEADER_MISMATCH,
    ERR_UNSUPPORTED_PROTOCOL_VERSION,
    HEADER_METHOD,
    HEADER_NAME,
    HEADER_PARAM_PREFIX,
    HEADER_PROTOCOL_VERSION,
    LEGACY_VERSIONS,
    META_CLIENT_CAPABILITIES,
    META_CLIENT_INFO,
    META_PROTOCOL_VERSION,
    MODERN_VERSIONS,
    NAME_BEARING_METHODS,
    encode_header_value,
    mcp_name_for,
    x_mcp_header_annotations,
    x_mcp_param_headers,
)
from .meta_identity import (
    ADMIN_NAMES,
    CLIENT_NAMES,
    IDENTITY_NAMES,
    SCOPE_NAMES,
    SUBJECT_NAMES,
    TENANT_NAMES,
    candidate_names,
    has_identity_word,
    is_identity_key,
)
from .types import ThreatCategory


class RequestMetadataError(CoSAIException):
    """T7: envelope rejected; ``code`` is the JSON-RPC error code, HTTP status 400.

    ``reason`` is a fixed scanner-side label (never request content) naming the
    failed check, for audit logs.
    """

    threat = ThreatCategory.T7
    json_rpc_code = -32020
    http_status = 400

    def __init__(self, code: int, message: str, data: Any = None, *,
                 reason: str = "invalid_request") -> None:
        super().__init__(message)
        self.code = code
        self.json_rpc_code = code          # per-instance: -32020 / -32022 / -32602 / -32600
        self.data = data
        self.reason = reason

    def to_jsonrpc_error(self) -> dict[str, Any]:
        err: dict[str, Any] = {"code": self.code, "message": str(self)}
        if self.data is not None:
            err["data"] = self.data
        return err


def _mismatch(header: str) -> RequestMetadataError:
    return RequestMetadataError(ERR_HEADER_MISMATCH, f"Header mismatch: {header}",
                                reason=header)


HeaderInput = (Mapping[str, str] | Mapping[bytes, bytes]
               | Iterable[tuple[str, str]] | Iterable[tuple[bytes, bytes]])


def _field(value: object) -> str:
    """Header name/value as text: bytes are RFC 9110 field octets (latin-1).
    Anything else is a caller bug — fail closed rather than stringify
    (``str(b"mcp-method")`` would hide a routing header from the gate)."""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("latin-1")
    raise TypeError("header names and values must be str or bytes")


_ROUTING_NAMES = frozenset({"mcp-protocol-version", "mcp-method", "mcp-name"})


def _is_routing(name: str) -> bool:
    return name in _ROUTING_NAMES or name.startswith("mcp-param-")


def _header_multimap(headers: HeaderInput, *, wsgi_environ: bool = False
                     ) -> dict[str, list[str]]:
    """Accepts a header mapping, str pairs, ASGI ``(bytes, bytes)`` pairs, or
    a WSGI environ when the caller says so (``wsgi_environ=True``; only
    ``HTTP_*`` entries are read). The mode is never inferred from the data —
    a client can send a header named ``wsgi.input``.

    Outside WSGI mode, a name that only *aliases* a routing header
    ("Mcp_Method", "http_mcp_method") is rejected (-32020): proxies and
    frameworks disagree on whether such names are the routing header, so
    accepting or ignoring either way is a header/body split-brain.
    """
    out: dict[str, list[str]] = {}
    if wsgi_environ:
        if not isinstance(headers, Mapping):
            raise TypeError("wsgi_environ=True requires the environ mapping")
        for k, v in headers.items():
            if isinstance(k, str) and k.startswith("HTTP_"):
                name = k[5:].lower().replace("_", "-")
                out.setdefault(name, []).append(_field(v))
        return out
    pairs = headers.items() if isinstance(headers, Mapping) else headers
    for pair in pairs:
        try:
            if isinstance(pair, (str, bytes, bytearray)):   # "ab" would unpack
                raise TypeError
            k, v = pair
        except (TypeError, ValueError):
            raise TypeError("header pairs must be (name, value)") from None
        name = _field(k).strip().lower()
        alias = name.replace("_", "-")
        alias = alias[5:] if alias.startswith("http-") else alias
        if alias != name and _is_routing(alias):
            raise _mismatch("header-alias")    # fixed label, never request text
        # Values are compared exactly (servers already trim OWS); padding is
        # a mismatch, never silently normalized.
        out.setdefault(name, []).append(_field(v))
    return out


def _arg_at(arguments: Any, path: tuple[str, ...]) -> Any:
    node = arguments
    for step in path:
        if not isinstance(node, Mapping) or step not in node:
            return None
        node = node[step]
    return node


def validate_request_metadata(
    headers: HeaderInput,
    body: Any,
    *,
    supported_versions: Iterable[str] = MODERN_VERSIONS,
    tool_schemas: Mapping[str, Any] | None = None,
    wsgi_environ: bool = False,
) -> str:
    """Validate a modern Streamable-HTTP request envelope; return its protocol version.

    *headers* may be a mapping, the raw list of (name, value) pairs (str or
    ASGI bytes), or — only with ``wsgi_environ=True`` — a WSGI environ, of
    which just the ``HTTP_*`` entries are read. Pass the raw list when the
    framework keeps duplicates: a routing header that appears more than once
    is rejected (an intermediary may pick a different copy than the server).
    Unsupported header shapes or types raise ``TypeError``.
    Limitation: in WSGI mode the server has already folded duplicate and
    underscore-variant headers into one ``HTTP_*`` entry, so they cannot be
    detected here; prefer raw ASGI pairs where the framework provides them.

    Raises :class:`RequestMetadataError`:

    * -32600 — body is not a single JSON-RPC request object (batches included);
    * -32022 — unsupported protocol version (``data.supported`` lists ours);
    * -32602 — ``_meta`` protocol version missing, or a name-bearing method
      without a string name/uri;
    * -32020 — ``MCP-Protocol-Version`` / ``Mcp-Method`` / ``Mcp-Name`` /
      ``Mcp-Param-*`` missing, duplicated, malformed, or disagreeing with the body.

    ``tool_schemas`` maps tool name → inputSchema so ``x-mcp-header``
    parameters can be checked on ``tools/call``. Without it, a ``tools/call``
    carrying any ``Mcp-Param-*`` header is rejected (it cannot be verified);
    with it, a tool absent from the map is rejected.
    """
    hdrs = _header_multimap(headers, wsgi_environ=wsgi_environ)

    def _single(name: str) -> str | None:
        values = hdrs.get(name.lower())
        if values is None:
            return None
        if len(values) != 1:
            raise _mismatch(name)
        return values[0]

    supported = sorted(set(supported_versions))

    def _unsupported(requested: Any) -> RequestMetadataError:
        return RequestMetadataError(ERR_UNSUPPORTED_PROTOCOL_VERSION,
                                    "Unsupported protocol version",
                                    {"supported": supported, "requested": str(requested)[:64]},
                                    reason="unsupported_version")

    def _legacy_gate() -> None:
        """Before any legacy-fallback signal: a request carrying modern
        routing headers is NOT legacy. An intermediary may already have routed
        on those headers, so the body must not be executed by a legacy handler
        (header/body split-brain via fallback) — reject with -32020."""
        for name in (HEADER_METHOD, HEADER_NAME):
            if name.lower() in hdrs:
                raise _mismatch(name)
        if any(h.startswith(HEADER_PARAM_PREFIX.lower()) for h in hdrs):
            raise _mismatch(HEADER_PARAM_PREFIX + "*")
        hv = _single(HEADER_PROTOCOL_VERSION)
        if hv is not None and hv not in LEGACY_VERSIONS:
            if hv in supported:
                raise _mismatch(HEADER_PROTOCOL_VERSION)
            raise _unsupported(hv)

    if isinstance(body, (list, tuple)):
        # JSON-RPC batch (2025-03-26 legacy): the only fallback-eligible -32600.
        _legacy_gate()
        raise RequestMetadataError(-32600, "Invalid Request", reason="batch")
    if isinstance(body, Mapping) and "method" not in body:
        # A response / non-request object: never a legacy-fallback signal.
        raise RequestMetadataError(-32600, "Invalid Request", reason="not_a_request")
    if not isinstance(body, Mapping) or not isinstance(body.get("method"), str):
        raise RequestMetadataError(-32600, "Invalid Request", reason="invalid_request")
    method: str = body["method"]
    raw_params = body.get("params")
    params: Mapping[str, Any] = raw_params if isinstance(raw_params, Mapping) else {}
    raw_meta = params.get("_meta")
    meta: Mapping[str, Any] | None = raw_meta if isinstance(raw_meta, Mapping) else None
    header_version = _single(HEADER_PROTOCOL_VERSION)
    version = meta.get(META_PROTOCOL_VERSION) if meta is not None else None

    if raw_meta is not None and meta is None or (
            meta is not None and META_PROTOCOL_VERSION in meta and not isinstance(version, str)):
        # Present but malformed: never the missing_meta fallback signal.
        raise RequestMetadataError(-32602, "Invalid _meta", reason="invalid_meta")
    if not isinstance(version, str):
        _legacy_gate()
        raise RequestMetadataError(-32602, "Missing required _meta protocol fields",
                                   reason="missing_meta")
    if header_version is None or header_version != version:
        raise _mismatch(HEADER_PROTOCOL_VERSION)
    if version not in supported:
        raise _unsupported(version)

    if _single(HEADER_METHOD) != method:
        raise _mismatch(HEADER_METHOD)

    raw_name = _single(HEADER_NAME)
    if method in NAME_BEARING_METHODS:
        expected_name = mcp_name_for(method, dict(params))
        if expected_name is None:
            raise RequestMetadataError(-32602, "Invalid params", reason="invalid_name")
        # Canonical encoding only: base64-wrapping a plain-ASCII name would hide
        # it from intermediaries that match literal names.
        try:
            canonical = encode_header_value(expected_name)
        except UnicodeEncodeError:       # lone surrogate: not a valid name
            raise RequestMetadataError(-32602, "Invalid params",
                                       reason="invalid_name") from None
        if raw_name is None or raw_name != canonical:
            raise _mismatch(HEADER_NAME)
    elif raw_name is not None:
        raise _mismatch(HEADER_NAME)

    prefix = HEADER_PARAM_PREFIX.lower()
    present = {h for h in hdrs if h.startswith(prefix)}
    if method != "tools/call" or tool_schemas is None:
        # No verifiable x-mcp-header annotation: any Mcp-Param-* header is an
        # unchecked routing value an intermediary might trust.
        if present:
            raise _mismatch(HEADER_PARAM_PREFIX + "*")
    else:
        tool = params.get("name")
        if not isinstance(tool, str) or tool not in tool_schemas:
            raise RequestMetadataError(-32602, "Unknown tool", reason="unknown_tool")
        schema = tool_schemas[tool]
        try:
            expected = {k.lower(): v for k, v in x_mcp_param_headers(
                schema, params.get("arguments"), strict=True).items()}
        except UnicodeEncodeError:
            raise _mismatch(HEADER_PARAM_PREFIX + "*") from None
        annotations = x_mcp_header_annotations(schema)
        declared = {(HEADER_PARAM_PREFIX + n).lower() for n, _ in annotations}
        if present - declared:
            # Unannotated (or invalidly annotated) parameter header.
            raise _mismatch(HEADER_PARAM_PREFIX + "*")
        for name, path in annotations:
            header = (HEADER_PARAM_PREFIX + name).lower()
            raw = _single(header)
            want = expected.get(header)
            if want is None:
                if _arg_at(params.get("arguments"), path) is not None:
                    # Present but not canonically renderable (integral float,
                    # int beyond 2^53, wrong type): the server would execute a
                    # value no intermediary could see in the header.
                    raise _mismatch(HEADER_PARAM_PREFIX + name)
                # Argument absent/null: a header for it would let an
                # intermediary route on a value the server never executes.
                if raw is not None:
                    raise _mismatch(HEADER_PARAM_PREFIX + name)
                continue
            if raw is None or raw != want:
                # Exact match on the canonical rendering — no numeric
                # coercion ("5.0", "1_0", "1e1") and no gratuitous base64.
                raise _mismatch(HEADER_PARAM_PREFIX + name)
    return version


# ---------------------------------------------------------------------------
# _meta identity reconciliation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Identity established by the access token, mTLS peer, or workload identity."""

    subject: str
    tenant: str | None = None
    client_id: str | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)


class MetaTrustError(AuthorizationError):
    """A ``_meta`` identity/role claim conflicts with the authenticated principal."""

    def __init__(self, keys: list[str]) -> None:
        # Only key NAMES — never the (attacker-supplied) claimed values.
        super().__init__("_meta claims conflict with the authenticated principal: "
                         + ", ".join(sorted(keys))[:300])
        self.keys = tuple(sorted(keys))


_PROTOCOL_KEYS = frozenset({META_PROTOCOL_VERSION})
_TRACE_KEYS = frozenset({"traceparent", "tracestate", "baggage"})
# Self-reported display/capability objects: never an identity source, but
# still inspected so they cannot smuggle identity claims.
_SELF_REPORTED_KEYS = frozenset({META_CLIENT_INFO, META_CLIENT_CAPABILITIES})
_MAX_META_DEPTH = 4
# clientInfo / clientCapabilities are spec-shaped objects (extensions nest
# deeper than vendor claims do).
_MAX_SELF_REPORTED_DEPTH = 8


def _as_set(value: Any) -> set[str] | None:
    if isinstance(value, str):
        return set(value.replace(",", " ").split())
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return set(value)
    return None


def _claim_conflicts(names: set[str], value: Any, principal: AuthenticatedPrincipal) -> bool:
    if names & SUBJECT_NAMES:
        return not (isinstance(value, str) and value == principal.subject)
    if names & TENANT_NAMES:
        return not (isinstance(value, str) and value == principal.tenant)
    if names & CLIENT_NAMES:
        return not (isinstance(value, str) and value == principal.client_id)
    if names & SCOPE_NAMES:
        claimed = _as_set(value)
        return claimed is None or not claimed <= set(principal.scopes)
    if names & ADMIN_NAMES:
        # Scalar only: a mapping/list value could otherwise carry nested
        # claims past an admin-scoped principal.
        if not (value is None or isinstance(value, (bool, int, str))):
            return True
        return bool(value not in (False, None, 0, "false") and "admin" not in principal.scopes)
    return False


def _safe_key(key: str) -> str:
    """Key path for errors/audit: printable only (no CR/LF/NUL/U+2028…), capped."""
    return "".join(c if c.isprintable() else "?" for c in key[:128])


def _trace_key_invalid(key: str, value: Any) -> bool:
    """Trace keys must be well-formed strings; baggage may not carry identity."""
    from .tracecontext import parse_traceparent

    if not isinstance(value, str) or len(value) > 8192:
        return True
    if key == "traceparent":
        return parse_traceparent(value) is None
    if key in ("baggage", "tracestate"):
        for member in value.split(","):
            # Baggage: "key=value;prop=x;prop2" — every key and property key
            # is checked, percent/plus-decoded (OTel propagators unquote them).
            for part in member.split(";") if key == "baggage" else [member]:
                pkey = part.partition("=")[0].strip()
                if "%" in pkey or "+" in pkey or is_identity_key(pkey):
                    return True
    return False


def reconcile_meta(
    meta: Mapping[str, Any] | None,
    principal: AuthenticatedPrincipal,
    *,
    allowed_keys: Iterable[str] | None = None,
    on_mismatch: Callable[[tuple[str, ...]], None] | None = None,
) -> None:
    """Reject ``_meta`` identity/role claims that conflict with *principal*.

    Every ``_meta`` key (any vendor prefix; nested mappings and lists up to 4
    levels, including inside ``clientInfo`` / ``clientCapabilities``) is
    checked:

    * a recognised subject / tenant / client id / role-scope / admin name must
      restate the authenticated identity (roles/scopes: a subset of the
      principal's scopes);
    * any other key containing an identity word (user, tenant, org, role,
      owner, delegate, …) is rejected outright — it cannot be reconciled;
    * ``traceparent`` / ``tracestate`` / ``baggage`` must be well-formed
      strings, and baggage may not carry identity keys.

    Name matching is a safety net, not the control: application code MUST
    take identity only from *principal*, never from ``_meta``. For strict
    deployments pass *allowed_keys*: any top-level key outside it and the
    reserved protocol/trace keys is rejected outright.

    Calls *on_mismatch* with the offending key paths (names only, never
    values) before raising :class:`MetaTrustError`.
    """
    if not meta:
        return
    bad: list[str] = []
    reserved = _PROTOCOL_KEYS | _TRACE_KEYS | _SELF_REPORTED_KEYS
    allow = None if allowed_keys is None else set(allowed_keys) | reserved

    def _visit(key_s: str, value: Any, path: str, depth: int, limit: int,
               operator_approved: bool = False) -> None:
        # MCP prefix grammar applies to top-level _meta keys only.
        prefixed = depth == 0
        names = candidate_names(key_s, prefixed=prefixed)
        if names & IDENTITY_NAMES:
            if _claim_conflicts(names, value, principal):
                bad.append(path)
            else:
                _descend(value, path, depth, limit)   # defense in depth
            return
        # An operator-allowlisted key ("x/userAgent") is exempt from the
        # identity-WORD heuristic, never from exact identity names.
        if not operator_approved and has_identity_word(key_s, prefixed=prefixed):
            bad.append(path)
            return
        _descend(value, path, depth, limit)

    def _descend(value: Any, path: str, depth: int, limit: int) -> None:
        if not isinstance(value, (Mapping, list, tuple)) or not value:
            return
        if depth + 1 >= limit:
            bad.append(path)          # too deep to inspect: fail closed
            return
        if isinstance(value, Mapping):
            for k, v in value.items():
                _visit(str(k), v, f"{path}>{k}", depth + 1, limit)
        else:
            for i, item in enumerate(value[:256]):
                _descend(item, f"{path}>{i}", depth + 1, limit)
            if len(value) > 256:
                bad.append(path)

    for key, value in meta.items():
        key_s = str(key)
        if key_s in _PROTOCOL_KEYS:
            if not (isinstance(value, str) and len(value) <= 64):
                bad.append(key_s)       # reserved key cannot carry structure
            continue
        if key_s.count("/") > 1:
            # MCP _meta grammar: the prefix ends at the first '/', and names
            # cannot contain one. Non-conforming keys are not inspected by
            # name, so reject them.
            bad.append(key_s)
            continue
        if key_s in _TRACE_KEYS:
            if _trace_key_invalid(key_s, value):
                bad.append(key_s)
            continue
        if key_s in _SELF_REPORTED_KEYS:
            _descend(value, key_s, 0, _MAX_SELF_REPORTED_DEPTH)
            continue
        if allow is not None and key_s not in allow:
            bad.append(key_s)
            continue
        _visit(key_s, value, key_s, 0, _MAX_META_DEPTH,
               operator_approved=allow is not None)

    if bad:
        keys = tuple(sorted(_safe_key(k) for k in bad))[:32]
        if on_mismatch is not None:
            on_mismatch(keys)
        raise MetaTrustError(list(keys))
