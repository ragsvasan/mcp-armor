"""Security regression tests for the mcp-armor sidecar reverse proxy.

Covers three findings from the 2026-07-17 audit, all rooted in what the forward
hop puts on the wire to the (untrusted, separate-trust-domain) upstream:

- **H2** — the client ``Content-Length`` must be dropped so httpx reframes the
  body from ``content=``; a client CL that disagrees with the framed body (a
  CL/TE desync) must not survive to the upstream and smuggle a second,
  uninspected request past the guard.
- **M6** — with ``strip_upstream_auth`` enabled, the client credentials
  (``Authorization``/``Cookie``/``DPoP``) must not reach a compromised upstream
  that could harvest and replay them; with it disabled (default) the credential
  must still pass through (the opt-in contract).
- **LOW** — an unset ``allowed_path_prefix`` must emit the CORS-style startup
  warning that path lockdown is not enforced.

These enter at ``ForwardingApp`` directly with a raw ASGI scope so the exact
request headers (duplicate/oversized/credential) can be crafted — an HTTP client
would normalise them away. A raw-ASGI recording upstream captures precisely what
the sidecar forwarded.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from mcp_armor.sidecar import ForwardingApp

# asyncio_mode = "auto" (pyproject) auto-marks async tests; no module pytestmark.


class _RecordingUpstream:
    """Raw-ASGI upstream that records the headers it received on each request.

    The sidecar forwards to this via an httpx ASGITransport, so ``received_headers``
    is exactly what went on the wire after the sidecar's header rewrite.
    """

    def __init__(self) -> None:
        self.received_headers: list[dict[str, list[str]]] = []

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":  # pragma: no cover - not driven here
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        hdrs: dict[str, list[str]] = {}
        for k, v in scope.get("headers", []):
            hdrs.setdefault(k.decode("latin-1").lower(), []).append(v.decode("latin-1"))
        self.received_headers.append(hdrs)
        parts: list[bytes] = []
        more = True
        while more:
            m = await receive()
            parts.append(m.get("body", b""))
            more = m.get("more_body", False)
        # Prove the sidecar delivered the FULL body regardless of the client CL.
        received_len = len(b"".join(parts))
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"len": received_len}}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})


def _scope(headers: list[tuple[bytes, bytes]]) -> dict:
    return {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": headers,
        "client": ("1.2.3.4", 5555),
    }


async def _drive(forwarder: ForwardingApp, scope: dict, body: bytes) -> None:
    async def _recv() -> dict:
        return {"type": "http.request", "body": body, "more_body": False}

    async def _send(_m: dict) -> None:
        return None

    await forwarder(scope, _recv, _send)


# ---------------------------------------------------------------------------
# H2 — request smuggling via un-stripped client Content-Length
# ---------------------------------------------------------------------------


async def test_regression_sidecar_strips_client_content_length() -> None:
    """The forwarded request must carry Content-Length == len(body) even when the
    client sent a smaller Content-Length together with Transfer-Encoding: chunked.

    Pre-fix, the client ``content-length: 3`` was copied into the forwarded headers
    and httpx honoured it over ``content=body`` — the upstream would frame 3 bytes
    as this request and treat the remaining bytes as a smuggled second request.
    """
    upstream = _RecordingUpstream()
    forwarder = ForwardingApp(
        "http://upstream.test", transport=httpx.ASGITransport(app=upstream)
    )
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"pad": "A" * 64}},
        }
    ).encode()
    assert len(body) > 3  # the client will lie and claim only 3 bytes

    # Client frames by TE:chunked but declares a tiny Content-Length — the classic
    # CL/TE desync used to smuggle the trailing bytes past a downstream parser.
    scope = _scope(
        [
            (b"content-length", b"3"),
            (b"transfer-encoding", b"chunked"),
        ]
    )
    await _drive(forwarder, scope, body)

    hdrs = upstream.received_headers[0]
    # httpx recomputed CL authoritatively from content=body; the client's "3" is gone.
    assert hdrs.get("content-length") == [str(len(body))]
    assert hdrs.get("content-length") != ["3"]
    # Transfer-Encoding is hop-by-hop and must never reach the upstream, so the
    # upstream cannot re-frame by TE either.
    assert "transfer-encoding" not in hdrs


# ---------------------------------------------------------------------------
# M6 — client credential passthrough to a separate-trust-domain upstream
# ---------------------------------------------------------------------------


async def test_sidecar_strips_authorization_when_configured() -> None:
    """With strip_upstream_auth=True, Authorization/Cookie/DPoP are dropped before
    the upstream hop so a compromised upstream cannot harvest the client's token."""
    upstream = _RecordingUpstream()
    forwarder = ForwardingApp(
        "http://upstream.test",
        strip_upstream_auth=True,
        transport=httpx.ASGITransport(app=upstream),
    )
    body = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}'
    scope = _scope(
        [
            (b"authorization", b"Bearer super-secret-jwt"),
            (b"cookie", b"session=abc123"),
            (b"dpop", b"eyJ-dpop-proof"),
        ]
    )
    await _drive(forwarder, scope, body)

    hdrs = upstream.received_headers[0]
    assert "authorization" not in hdrs
    assert "cookie" not in hdrs
    assert "dpop" not in hdrs


async def test_sidecar_forwards_authorization_by_default() -> None:
    """Opt-in contract: the default (strip_upstream_auth=False) preserves the
    transparent passthrough — the credential still reaches a co-trusted upstream.
    Guards against a future silent flip of the default to strip."""
    upstream = _RecordingUpstream()
    forwarder = ForwardingApp(
        "http://upstream.test", transport=httpx.ASGITransport(app=upstream)
    )
    body = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}'
    scope = _scope([(b"authorization", b"Bearer super-secret-jwt")])
    await _drive(forwarder, scope, body)

    hdrs = upstream.received_headers[0]
    assert hdrs.get("authorization") == ["Bearer super-secret-jwt"]


# ---------------------------------------------------------------------------
# LOW — path-lockdown startup warning when allowed_path_prefix is unset
# ---------------------------------------------------------------------------


def test_sidecar_warns_when_path_prefix_unset(caplog) -> None:
    """An unset allowed_path_prefix emits the CORS-style 'lockdown NOT enforced'
    warning; setting a prefix suppresses it."""
    with caplog.at_level(logging.WARNING, logger="mcp_armor.sidecar"):
        ForwardingApp("http://upstream.test")
    assert any(
        "allowed_path_prefix not configured" in r.getMessage()
        and "NOT enforced" in r.getMessage()
        for r in caplog.records
    )

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="mcp_armor.sidecar"):
        ForwardingApp("http://upstream.test", allowed_path_prefix="/api/mcp")
    assert not any(
        "allowed_path_prefix not configured" in r.getMessage() for r in caplog.records
    )
