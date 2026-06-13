"""B5 — per-request overhead of the mcp-armor engine chain.

Measures p50/p99/p999 wall-clock of one full request→response pass through the
guard (all engines that run on the hot path), excluding the upstream tool. Run:

    ARMOR_SESSION_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))") \
        python benchmarks/chain_overhead.py [iterations]

Numbers are machine-dependent; publish them alongside the CPU they were taken on.
"""

from __future__ import annotations

import asyncio
import os
import statistics
import sys
import tempfile
import time
from types import MappingProxyType

os.environ.setdefault("ARMOR_SESSION_SECRET", "bench-" + "s" * 40)

from joserfc import jwt as _jwt  # noqa: E402

from mcp_armor.context import CoSAIContext  # noqa: E402
from mcp_armor.engines.audit import AuditEngine  # noqa: E402
from mcp_armor.engines.auth import AuthEngine  # noqa: E402
from mcp_armor.engines.authz import AuthzEngine  # noqa: E402
from mcp_armor.engines.boundary import BoundaryEngine  # noqa: E402
from mcp_armor.engines.integrity import IntegrityEngine  # noqa: E402
from mcp_armor.engines.network import NetworkEngine  # noqa: E402
from mcp_armor.engines.protection import ProtectionEngine  # noqa: E402
from mcp_armor.engines.resources import ResourceEngine  # noqa: E402
from mcp_armor.engines.session import SessionEngine  # noqa: E402
from mcp_armor.engines.trust import TrustEngine  # noqa: E402
from mcp_armor.engines.validation import ValidationEngine  # noqa: E402
from mcp_armor.guard import CoSAIGuard  # noqa: E402
from mcp_armor.types import MCPRequest, MCPResponse  # noqa: E402

_OCT_JWKS = {"keys": [{"kty": "oct", "k": "c2VjcmV0LWtleS1mb3ItYmVuY2htYXJraW5n", "kid": "b"}]}


def _token() -> str:
    from joserfc.jwk import OctKey

    key = OctKey.import_key(_OCT_JWKS["keys"][0])
    claims = {"sub": "bench-user", "exp": int(time.time()) + 600, "scope": "tools:call"}
    return _jwt.encode({"alg": "HS256", "kid": "b"}, claims, key)


def _build_guard(audit_path: str, include_audit: bool = True) -> CoSAIGuard:
    # Full hot-path chain. require_dpop/require_jti off so a plain HS256 bearer
    # token verifies; everything else is the production engine set.
    engines = []
    if include_audit:
        engines.append(AuditEngine(path=audit_path, verify_on_startup=False, require_hmac=False))
    engines += [
        AuthEngine(jwks=_OCT_JWKS, require_dpop=False, require_jti=False),
        SessionEngine(),
        NetworkEngine(),
        AuthzEngine(tool_policies={}, default_deny=False),
        ValidationEngine(strict_schema=False),  # no manifest needed for a pure-overhead measure
        BoundaryEngine(),
        ResourceEngine(max_calls_per_session=10**9),
        IntegrityEngine(),
        ProtectionEngine(profile="pci"),
        TrustEngine(),
    ]
    return CoSAIGuard(engines)


async def _bench(iterations: int, include_audit: bool = True) -> None:
    label = "full chain (with T12 audit disk I/O)" if include_audit else "CPU chain (no audit I/O)"
    print(f"\n=== {label} ===")
    tmp = tempfile.mkdtemp()
    guard = _build_guard(os.path.join(tmp, "audit.jsonl"), include_audit=include_audit)
    await guard.startup()

    session_id = guard.mint_session_id("http")
    headers = MappingProxyType({"authorization": f"Bearer {_token()}"})
    base_ctx = CoSAIContext.new(session_id, transport="http")
    base_ctx = await guard.open_session(base_ctx)

    req = MCPRequest(
        method="tools/call",
        params=MappingProxyType({"name": "echo", "arguments": {"message": "hello world"}}),
        session_id=session_id,
        raw_headers=headers,
        transport="http",
    )
    resp = MCPResponse.from_text("Echo: hello world")

    # warmup
    for _ in range(200):
        ctx = await guard._run_request(base_ctx, req)
        await guard._run_response(ctx, resp)

    samples: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        ctx = await guard._run_request(base_ctx, req)
        await guard._run_response(ctx, resp)
        samples.append((time.perf_counter() - t0) * 1e6)  # microseconds

    samples.sort()

    def p(q: float) -> float:
        return samples[min(len(samples) - 1, int(q * len(samples)))]

    print(f"iterations      : {iterations}")
    print(f"engines on path : {len(guard._engines)} (request) + {len(guard._engines)} (response)")
    print(f"mean   : {statistics.mean(samples):8.1f} µs")
    print(f"p50    : {p(0.50):8.1f} µs")
    print(f"p90    : {p(0.90):8.1f} µs")
    print(f"p99    : {p(0.99):8.1f} µs")
    print(f"p99.9  : {p(0.999):8.1f} µs")
    print(f"max    : {samples[-1]:8.1f} µs")


async def _main(n: int) -> None:
    await _bench(n, include_audit=False)
    await _bench(n, include_audit=True)


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20_000
    asyncio.run(_main(n))
