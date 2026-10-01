"""W3C Trace Context in MCP ``_meta`` — CoSAI v2.0 LO-03 (L3).

The 2026-07-28 spec reserves ``traceparent`` / ``tracestate`` / ``baggage`` in
``_meta``. v2.0 L3 requires: propagated baggage allowlisted by key and
size-bounded, never carrying tenant or user data across a trust boundary; and
server-supplied trace context MUST NOT overwrite the trace identity the client
established.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import quote, unquote

from .meta_identity import is_identity_key

_TRACEPARENT_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_BAGGAGE_KEY_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
_MAX_BAGGAGE_BYTES = 1024
# Compared after _norm_key (lowercase, separators removed): "tenant-id",
# "Tenant.ID" and "tenant_id" are all "tenantid".
_SENSITIVE_BAGGAGE_KEYS = frozenset({
    "user", "userid", "username", "email", "sub", "subject", "principal", "tenant",
    "tenantid", "org", "orgid", "organization", "organisation", "account", "accountid",
    "session", "sessionid", "token", "accesstoken", "authorization", "clientid",
    "enduser", "enduserid", "enduserrole", "enduserscope", "apikey", "password",
    "secret", "customerid", "uid",
})
_MAX_BAGGAGE_INPUT_CHARS = 8192   # W3C Baggage limit


def _norm_key(key: str) -> str:
    return re.sub(r"[-._\s]", "", key.lower())


def parse_traceparent(value: Any) -> tuple[str, str, str] | None:
    """Return (trace_id, parent_id, flags) for a valid version-00 traceparent."""
    if not isinstance(value, str):
        return None
    m = _TRACEPARENT_RE.fullmatch(value.strip())
    if m is None or m.group(1) == "0" * 32 or m.group(2) == "0" * 16:
        return None
    return m.group(1), m.group(2), m.group(3)


def sanitize_baggage(value: Any, allowed_keys: Iterable[str],
                     *, max_bytes: int = _MAX_BAGGAGE_BYTES) -> str | None:
    """Keep only allowlisted, non-sensitive keys; bound total size.

    Returns the sanitized ``baggage`` string, or None if nothing survives.
    Sensitive keys (user/tenant identifiers, tokens) are dropped even when
    allowlisted — they must never cross a trust boundary.
    """
    if not isinstance(value, str) or len(value) > _MAX_BAGGAGE_INPUT_CHARS:
        return None
    allowed = {k.lower() for k in allowed_keys
               if _norm_key(k) not in _SENSITIVE_BAGGAGE_KEYS and not is_identity_key(k)}
    kept: list[str] = []
    size = 0
    for member in value.split(",", 64)[:64]:
        if len(member) > max_bytes:
            continue
        key, sep, rest = member.strip().partition("=")
        key = key.strip()
        if not sep or not _BAGGAGE_KEY_RE.match(key) or key.lower() not in allowed \
                or "%" in key or "+" in key:
            continue
        val = quote(unquote(rest.split(";", 1)[0].strip()), safe="")
        entry = f"{key}={val}"
        if size + len(entry) + (1 if kept else 0) > max_bytes:
            break
        kept.append(entry)
        size += len(entry) + (1 if len(kept) > 1 else 0)
    return ",".join(kept) or None


def _format(tp: tuple[str, str, str]) -> str:
    return f"00-{tp[0]}-{tp[1]}-{tp[2]}"


def preserve_client_trace(client_meta: Mapping[str, Any] | None,
                          server_meta: Mapping[str, Any] | None) -> tuple[dict[str, Any], bool]:
    """Merge server-returned trace context without letting it replace the
    client's trace identity.

    Returns (trace fields to keep, overwrite_attempted). If the client
    established a valid traceparent, the server's traceparent is kept only if
    it carries the SAME trace-id (a child span); otherwise the client's is kept
    and ``overwrite_attempted`` is True (log it as security-relevant).
    """
    client_tp = parse_traceparent((client_meta or {}).get("traceparent"))
    server_tp = parse_traceparent((server_meta or {}).get("traceparent"))
    out: dict[str, Any] = {}
    # Always emit the normalized form, never the raw (possibly padded) input.
    if client_tp is None:
        if server_tp is not None:
            out["traceparent"] = _format(server_tp)
        return out, False
    if server_tp is not None and server_tp[0] == client_tp[0]:
        out["traceparent"] = _format(server_tp)
        return out, False
    out["traceparent"] = _format(client_tp)
    return out, server_tp is not None or "traceparent" in (server_meta or {})
