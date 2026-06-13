"""B8 — loopback-hop overhead of the mcp-armor sidecar.

`chain_overhead.py` measures the in-process engine chain. This measures the OTHER
cost the sidecar adds: the extra network hop. It stands up two real uvicorn
servers on loopback (a stub upstream, and the sidecar in front of it) and times a
`tools/call` round-trip both ways:

    direct  : client ─▶ upstream
    sidecar : client ─▶ sidecar (ArmorMiddleware + forward) ─▶ upstream

The reported delta is the per-request cost of routing through the sidecar — the
forwarding hop plus ArmorMiddleware's buffer/replay — over and above hitting the
upstream directly. A minimal guard is used so the number reflects the HOP, not the
engines; add the engine-chain figure from chain_overhead.py for the full per-
request picture. Run::

    ARMOR_SESSION_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))") \
        python benchmarks/sidecar_overhead.py [iterations]

Numbers are machine-dependent; publish them alongside the CPU they were taken on.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import threading
import time

os.environ.setdefault("ARMOR_SESSION_SECRET", "bench-" + "s" * 40)

import httpx  # noqa: E402
import uvicorn  # noqa: E402
from starlette.applications import Starlette  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402

from mcp_armor.engines.session import SessionEngine  # noqa: E402
from mcp_armor.guard import CoSAIGuard  # noqa: E402
from mcp_armor.sidecar import build_app  # noqa: E402


async def _upstream_endpoint(request: Request) -> JSONResponse:
    payload = await request.json()
    method = payload.get("method", "")
    req_id = payload.get("id")
    if method == "initialize":
        result: dict = {"protocolVersion": "2025-06-18"}
    else:
        result = {"content": [{"type": "text", "text": "ok"}]}
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})


def _upstream_app() -> Starlette:
    return Starlette(routes=[Route("/{path:path}", _upstream_endpoint, methods=["POST"])])


class _Server:
    """Run a uvicorn server in a background thread on a fixed loopback port."""

    def __init__(self, app, port: int) -> None:
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self.port = port

    def start(self) -> None:
        self._thread.start()
        while not self._server.started:
            time.sleep(0.02)

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)


def _percentiles(samples: list[float]) -> dict[str, float]:
    samples = sorted(samples)

    def p(q: float) -> float:
        return samples[min(len(samples) - 1, int(q * len(samples)))]

    return {
        "mean": statistics.mean(samples),
        "p50": p(0.50),
        "p90": p(0.90),
        "p99": p(0.99),
    }


def _bench_endpoint(base_url: str, headers: dict[str, str], iterations: int) -> list[float]:
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": "hello"}},
    }
    samples: list[float] = []
    with httpx.Client(base_url=base_url, timeout=10.0) as client:
        for _ in range(200):  # warmup
            client.post("/", json=call, headers=headers)
        for _ in range(iterations):
            t0 = time.perf_counter()
            client.post("/", json=call, headers=headers)
            samples.append((time.perf_counter() - t0) * 1e6)  # microseconds
    return samples


def main(iterations: int) -> None:
    upstream = _Server(_upstream_app(), port=8771)
    guard = CoSAIGuard([SessionEngine()])  # minimal guard — isolates the hop cost
    sidecar = _Server(
        build_app(upstream="http://127.0.0.1:8771", guard=guard, cors_origins=[]),
        port=8770,
    )
    upstream.start()
    sidecar.start()
    try:
        # A session id for the sidecar path (T7); the direct upstream ignores it.
        with httpx.Client(base_url="http://127.0.0.1:8770", timeout=10.0) as c:
            init = c.post("/", json={"jsonrpc": "2.0", "id": 0, "method": "initialize"})
            session_id = init.headers["mcp-session-id"]

        direct = _percentiles(_bench_endpoint("http://127.0.0.1:8771", {}, iterations))
        through = _percentiles(
            _bench_endpoint(
                "http://127.0.0.1:8770", {"mcp-session-id": session_id}, iterations
            )
        )
    finally:
        sidecar.stop()
        upstream.stop()

    print(f"\n=== sidecar loopback-hop overhead (iterations={iterations}) ===")
    print(f"{'metric':>6} | {'direct':>10} | {'sidecar':>10} | {'added':>10}")
    print("-" * 46)
    for key in ("mean", "p50", "p90", "p99"):
        d, s = direct[key], through[key]
        print(f"{key:>6} | {d:8.1f}µs | {s:8.1f}µs | {s - d:8.1f}µs")
    print(
        "\nNote: minimal guard (SessionEngine only) — this is the HOP cost. "
        "Add the engine-chain cost from chain_overhead.py for the full per-request total."
    )
    summary = {
        "iterations": iterations,
        "direct_us": direct,
        "sidecar_us": through,
        "added_us": {k: through[k] - direct[k] for k in direct},
    }
    print("\nJSON:", json.dumps(summary))


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5_000
    main(n)
