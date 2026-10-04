"""OCSF API Activity (class 6003) events for MCP requests — CoSAI v2.0
LO-01 (keyed parameter digests, never raw params) and LO-04 (agentic
extension fields under ``unmapped.cosai_agentic``).

Ported from cosai-mcp ``cosai_mcp.telemetry.ocsf.build_mcp_api_activity``;
the event shape is identical apart from ``metadata.product``. Emit one event
per MCP request from your logging pipeline (e.g. an AuditEngine sink).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

_PRODUCT_NAME = "mcp-armor"
_VENDOR_NAME = "CoSAI"
_SCHEMA_VERSION = "2.0.0"
_API_ACTIVITY_CLASS_UID = 6003          # OCSF API Activity
_API_ACTIVITY_CATEGORY_UID = 6          # Application Activity
_DECISIONS = frozenset({"allow", "deny", "error"})


@dataclass(frozen=True)
class OcsfEvent:
    """Thin wrapper around an OCSF event dict."""

    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return dict(self.data)


def build_mcp_api_activity(
    *,
    server: str,
    mcp_method: str,
    decision: str,
    principal: str | None = None,
    tenant: str | None = None,
    mcp_name: str | None = None,
    params: Any = None,
    params_key: bytes | None = None,
    correlation_id: str | None = None,
    delegation_path: list[str] | tuple[str, ...] | None = None,
    attestation_state: str | None = None,
    trace_id: str | None = None,
    reason: str | None = None,
    timestamp_ms: int | None = None,
) -> OcsfEvent:
    """OCSF API Activity (6003) for one MCP request, with the CoSAI v2.0
    agentic extension fields (LO-04: delegation_path, attestation_state,
    correlation_id, mcp_method, mcp_name) under ``unmapped.cosai_agentic``.

    Parameters are NEVER logged raw — only an HMAC-SHA256 of their canonical
    JSON under the deployment secret *params_key* (≥32 bytes). A plain hash of
    low-entropy params (ids, emails) is dictionary-reversible, so without a key
    no parameter digest is emitted (LO-01: "raw parameters … logged only after
    redaction, hashing, or tokenization"). *reason* should be a
    middleware-generated code, not attacker text.
    """
    import hashlib
    import hmac
    import json

    if decision not in _DECISIONS:
        raise ValueError(f"decision must be one of {sorted(_DECISIONS)}")
    ts_ms = timestamp_ms if timestamp_ms is not None else int(time.time() * 1000)
    if params_key is not None and len(params_key) < 32:
        raise ValueError("params_key must be at least 32 bytes")
    params_hash = None
    params_unserializable = False
    if params is not None and params_key is not None:
        try:
            # No default=str: non-JSON values must not collide with strings.
            canon = json.dumps(params, sort_keys=True, separators=(",", ":"),
                               allow_nan=False).encode()
        except (TypeError, ValueError, RecursionError):
            params_unserializable = True
        else:
            params_hash = hmac.new(params_key, canon, hashlib.sha256).hexdigest()

    def _cap(value: str | None, n: int = 256) -> str | None:
        return None if value is None else str(value)[:n]

    agentic: dict[str, Any] = {
        "mcp_method": _cap(mcp_method, 128),
        "mcp_name": _cap(mcp_name),
        "correlation_id": _cap(correlation_id, 128),
        "delegation_path": [str(h)[:256] for h in (delegation_path or ())][:32],
        "attestation_state": _cap(attestation_state, 64),
        "params_hmac_sha256": params_hash,
        "params_unserializable": params_unserializable,
        "trace_id": _cap(trace_id, 64),
        "decision": decision,
        "reason": _cap(reason),
    }
    event: dict[str, Any] = {
        "class_uid": _API_ACTIVITY_CLASS_UID,
        "class_name": "API Activity",
        "category_uid": _API_ACTIVITY_CATEGORY_UID,
        "category_name": "Application Activity",
        "activity_id": 99,
        "activity_name": "Other",
        "type_uid": _API_ACTIVITY_CLASS_UID * 100 + 99,
        "time": ts_ms,
        "severity_id": 1 if decision == "allow" else 3,
        "status_id": 1 if decision == "allow" else 2,   # 1 Success, 2 Failure
        "api": {"operation": _cap(mcp_method, 128),
                "service": {"name": "MCP", "uid": _cap(server)}},
        "actor": {"user": {"uid": _cap(principal)},
                  **({"tenant_uid": _cap(tenant)} if tenant else {})},
        "metadata": {
            "product": {"name": _PRODUCT_NAME, "vendor_name": _VENDOR_NAME},
            "version": _SCHEMA_VERSION,
            **({"correlation_uid": _cap(correlation_id, 128)} if correlation_id else {}),
        },
        "unmapped": {"cosai_agentic": agentic},
    }
    return OcsfEvent(data=event)
