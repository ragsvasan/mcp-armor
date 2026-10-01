"""MCP 2026-07-28 protocol constants and header helpers (ported from cosai-mcp).

Shared by the request-envelope checks (request_envelope.py): protocol
versions, reserved ``_meta`` keys, error codes, Streamable-HTTP routing headers,
the ``=?base64?…?=`` header-value encoding, and ``x-mcp-header`` parameter
mirroring.
"""

from __future__ import annotations

import base64
import re
from typing import Any

# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

MODERN_PROTOCOL_VERSION = "2026-07-28"
MODERN_VERSIONS: frozenset[str] = frozenset({MODERN_PROTOCOL_VERSION})

# Handshake-based revisions (initialize / initialized / Mcp-Session-Id).
LEGACY_VERSIONS: frozenset[str] = frozenset(
    {"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
)

# ---------------------------------------------------------------------------
# _meta keys (params._meta on every modern request)
# ---------------------------------------------------------------------------

META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"

# ---------------------------------------------------------------------------
# JSON-RPC error codes defined by 2026-07-28 (reserved range -32020..-32099)
# ---------------------------------------------------------------------------

ERR_HEADER_MISMATCH = -32020
ERR_MISSING_CLIENT_CAPABILITY = -32021
ERR_UNSUPPORTED_PROTOCOL_VERSION = -32022
MODERN_ERROR_CODES: frozenset[int] = frozenset(
    {ERR_HEADER_MISMATCH, ERR_MISSING_CLIENT_CAPABILITY, ERR_UNSUPPORTED_PROTOCOL_VERSION}
)

# ---------------------------------------------------------------------------
# HTTP request-metadata headers (Streamable HTTP, modern only)
# ---------------------------------------------------------------------------

HEADER_PROTOCOL_VERSION = "MCP-Protocol-Version"
HEADER_METHOD = "Mcp-Method"
HEADER_NAME = "Mcp-Name"
HEADER_PARAM_PREFIX = "Mcp-Param-"

# Methods whose params.name / params.uri is mirrored into Mcp-Name.
_NAME_BEARING_METHODS: dict[str, str] = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
}

_B64_PREFIX = "=?base64?"
_B64_SUFFIX = "?="
# RFC 9110 tchar — valid HTTP field-name token.
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_JS_SAFE_INT = 2**53 - 1



# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------

def build_request_meta(
    client_info: dict[str, str],
    client_capabilities: dict[str, Any],
    version: str = MODERN_PROTOCOL_VERSION,
) -> dict[str, Any]:
    """Return the required per-request ``_meta`` fields for a modern request."""
    return {
        META_PROTOCOL_VERSION: version,
        META_CLIENT_INFO: dict(client_info),
        META_CLIENT_CAPABILITIES: dict(client_capabilities),
    }


def with_request_meta(params: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *params* with the protocol ``_meta`` fields merged in.

    Keys already present in ``params['_meta']`` win: probes deliberately send
    spoofed or malformed ``_meta`` (T1 identity-claim tests), and the scanner
    must deliver exactly what the probe asked for.  A non-dict ``_meta`` is
    left untouched for the same reason.
    """
    out = dict(params)
    existing = out.get("_meta")
    if existing is None:
        out["_meta"] = dict(meta)
    elif isinstance(existing, dict):
        out["_meta"] = {**meta, **existing}
    return out


def encode_header_value(value: str) -> str:
    """Encode *value* for an ``Mcp-Name`` / ``Mcp-Param-*`` header.

    Plain visible ASCII passes through; anything else (non-ASCII, control
    characters, leading/trailing whitespace, or a value that itself matches
    the sentinel pattern) is carried as ``=?base64?<b64 of UTF-8>?=``.
    """
    safe = (
        value == value.strip()
        and all(c == "\t" or 0x20 <= ord(c) <= 0x7E for c in value)
        and not (value.startswith(_B64_PREFIX) and value.endswith(_B64_SUFFIX))
    )
    if safe:
        return value
    return _B64_PREFIX + base64.b64encode(value.encode("utf-8")).decode("ascii") + _B64_SUFFIX


def decode_header_value(value: str) -> str:
    """Inverse of :func:`encode_header_value` (used by the mock server)."""
    if value.startswith(_B64_PREFIX) and value.endswith(_B64_SUFFIX):
        inner = value[len(_B64_PREFIX):-len(_B64_SUFFIX)]
        return base64.b64decode(inner, validate=True).decode("utf-8")
    return value


NAME_BEARING_METHODS = frozenset(_NAME_BEARING_METHODS)


def mcp_name_for(method: str, params: dict[str, Any]) -> str | None:
    """Return the body value mirrored into ``Mcp-Name`` for *method*, if any."""
    field = _NAME_BEARING_METHODS.get(method)
    if field is None:
        return None
    value = params.get(field)
    return value if isinstance(value, str) else None


def request_metadata_headers(
    method: str, params: dict[str, Any], version: str = MODERN_PROTOCOL_VERSION,
) -> dict[str, str]:
    """Return the standard modern Streamable-HTTP request headers."""
    headers = {HEADER_PROTOCOL_VERSION: version, HEADER_METHOD: method}
    name = mcp_name_for(method, params)
    if name is not None:
        try:
            headers[HEADER_NAME] = encode_header_value(name)
        except UnicodeEncodeError:
            pass   # lone surrogate in a hostile name: send without Mcp-Name
    return headers


def _header_param_value(value: Any, *, strict: bool = False) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) > _JS_SAFE_INT:
            return None
        return str(value)
    if isinstance(value, str):
        try:
            return encode_header_value(value)
        except UnicodeEncodeError:
            if strict:
                raise
            return None
    return None


def x_mcp_param_headers(input_schema: Any, arguments: Any, *,
                        strict: bool = False) -> dict[str, str]:
    """Return ``Mcp-Param-{name}`` headers for ``x-mcp-header`` annotations.

    Only annotations reachable from the schema root through a chain of
    ``properties`` keys are honoured (spec constraint).  Annotations that
    violate the spec (non-token name, duplicate name, non-primitive target)
    are skipped: the scanner never *crashes* on a hostile schema, and the
    invalid annotation is left for a T3 manifest check to report.

    Deliberate protocol deviation: the spec says a conforming client MUST drop
    a tool with an invalid annotation from its ``tools/list`` view.  A security
    scanner must instead *see* hostile tool definitions, so the tool stays in
    the manifest and is probed; only the invalid header is withheld.
    """
    if not isinstance(arguments, dict):
        return {}
    headers: dict[str, str] = {}
    for name, path in x_mcp_header_annotations(input_schema):
        node: Any = arguments
        for step in path:
            if not isinstance(node, dict) or step not in node:
                node = None
                break
            node = node[step]
        encoded = _header_param_value(node, strict=strict)
        if encoded is not None:
            headers[HEADER_PARAM_PREFIX + name] = encoded
    return headers


def x_mcp_header_annotations(input_schema: Any) -> list[tuple[str, tuple[str, ...]]]:
    """Valid ``x-mcp-header`` annotations as (header name, property path).

    Valid = reachable through ``properties`` chains, RFC 9110 token name,
    case-insensitively unique, primitive (optionally nullable) target type.
    """
    if not isinstance(input_schema, dict):
        return []

    annotations: list[tuple[str, tuple[str, ...], Any]] = []

    def _walk(schema: dict[str, Any], path: tuple[str, ...], depth: int) -> None:
        if depth > 16:
            return
        props = schema.get("properties")
        if not isinstance(props, dict):
            return
        for key, sub in props.items():
            if not isinstance(sub, dict):
                continue
            ann = sub.get("x-mcp-header")
            if isinstance(ann, str):
                annotations.append((ann, (*path, key), sub.get("type")))
            _walk(sub, (*path, key), depth + 1)

    _walk(input_schema, (), 0)

    seen: set[str] = set()
    valid: list[tuple[str, tuple[str, ...]]] = []
    for name, path, typ in annotations:
        lowered = name.lower()
        if not _TOKEN_RE.match(name) or lowered in seen:
            continue
        seen.add(lowered)
        if isinstance(typ, list):
            # e.g. ["string", "null"] — nullable primitive
            non_null = [t for t in typ if t != "null"]
            typ = non_null[0] if len(non_null) == 1 else None
        if typ not in ("string", "integer", "boolean"):
            continue
        valid.append((name, path))
    return valid
