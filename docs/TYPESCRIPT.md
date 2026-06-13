# Using mcp-armor with TypeScript (and other non-Python) MCP servers

mcp-armor is a Python library — it cannot be `npm install`-ed into a TypeScript
project. To protect a non-Python MCP server, run mcp-armor as a **sidecar**: a
thin reverse proxy that sits in front of your server, runs all 12 CoSAI engines on
every JSON-RPC request and response, and forwards only clean traffic upstream.

This is a **shipped artifact**, not a copy-paste recipe:

- The module `mcp_armor.sidecar` ships in the package — run it with
  `python -m mcp_armor.sidecar` or the `mcp-armor-sidecar` console script.
- A `Dockerfile` and `docker-compose.sidecar.yml` ship in the repo; the release
  pipeline publishes an image to `ghcr.io/ragsvasan/mcp-armor-sidecar`.
- The loopback-hop overhead is **benchmarked** (numbers below).

```
MCP client ──▶ mcp-armor sidecar  ──▶ Your TypeScript server
               (Python, :8000)         (Node.js, :3000)
               all 12 engines run      only sees clean requests
```

---

## Option 1 — Sidecar proxy (shipped)

### Install and run

```bash
pip install "mcp-armor[sidecar]"          # pulls in httpx + uvicorn
cp cosai.yaml.example cosai.yaml          # edit for your deployment
export ARMOR_SESSION_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))")

mcp-armor-sidecar --config cosai.yaml --upstream http://localhost:3000
# equivalently: python -m mcp_armor.sidecar --config cosai.yaml --upstream http://localhost:3000
```

Point your MCP client at `:8000`. Your TypeScript server keeps running on `:3000`
and is never exposed directly.

### Configuration — flags and environment variables

Every flag has an environment-variable fallback (CLI wins over env over default):

| Flag | Env var | Default | Meaning |
|---|---|---|---|
| `-c`, `--config` | `ARMOR_CONFIG` | `cosai.yaml` | Path to the CoSAI policy file. |
| `-u`, `--upstream` | `ARMOR_UPSTREAM` | `http://localhost:3000` | Upstream MCP server URL. |
| `--host` | `ARMOR_SIDECAR_HOST` | `127.0.0.1` | Listen host (use `0.0.0.0` in a container). |
| `--port` | `ARMOR_SIDECAR_PORT` | `8000` | Listen port. |
| `--cors-origin` (repeatable) | `ARMOR_CORS_ORIGINS` (comma-separated) | unset | Allowed CORS origins (T7-001). Set to an explicit list, or pass none to leave CORS unenforced (a startup warning is emitted). A wildcard is never permitted. |
| `--max-body-bytes` | `ARMOR_MAX_BODY_BYTES` | adapter default | Request body size cap. |

`ARMOR_SESSION_SECRET` is **required** (the guard refuses to start without it) — it
keys the stateless HMAC session token (T7).

### Docker

```bash
docker build -t mcp-armor-sidecar .
docker run --rm -p 8000:8000 \
  -e ARMOR_SESSION_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))") \
  -e ARMOR_UPSTREAM=http://host.docker.internal:3000 \
  -v "$PWD/cosai.yaml:/app/cosai.yaml:ro" \
  mcp-armor-sidecar
```

Or pull the published image (released on every `vX.Y.Z` tag):

```bash
docker pull ghcr.io/ragsvasan/mcp-armor-sidecar:latest
```

### Docker Compose

The repo ships `docker-compose.sidecar.yml`. The key safety property: **only the
sidecar is published to the host** — the upstream server is reachable solely on the
internal compose network, so a client cannot bypass the guard by hitting `:3000`
directly.

```bash
export ARMOR_SESSION_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))")
docker compose -f docker-compose.sidecar.yml up --build
```

```yaml
services:
  mcp-armor:
    build: { context: ., dockerfile: Dockerfile }
    environment:
      ARMOR_SESSION_SECRET: ${ARMOR_SESSION_SECRET:?set ARMOR_SESSION_SECRET}
      ARMOR_UPSTREAM: http://mcp-upstream:3000
    volumes:
      - ./cosai.yaml:/app/cosai.yaml:ro
    ports:
      - "8000:8000"          # the ONLY port exposed to the host
    depends_on: [mcp-upstream]

  mcp-upstream:
    image: your-org/your-mcp-server:latest
    expose: ["3000"]          # NOT published — forces all traffic through the guard
```

### What the proxy covers

Every CoSAI control runs at the sidecar layer before any request reaches your
server (and on every response before it returns to the client):

| Control | Where it fires |
|---|---|
| T1 Auth / DPoP | Before request reaches upstream |
| T2 RBAC / destructive gate | Before request reaches upstream |
| T3 Input validation | Before request reaches upstream |
| T4 Prompt injection | Request args and upstream response |
| T5 PII detection | On response from upstream |
| T6 Tool manifest integrity | Per session |
| T7 Session fixation + CORS origin enforcement | Before request reaches upstream |
| T8 SSRF / network controls | Per request |
| T9 LLM output sanitization | On response from upstream |
| T10 Resource budgets + HTTP 429 + Retry-After | Per session in sidecar |
| T11 Supply chain | Per session |
| T12 Audit log | Every request + response, in sidecar |

> If your upstream server handles auth/authz natively, disable T1/T2 in
> `cosai.yaml` (`threats.T1.enabled: false`, `threats.T2.enabled: false`) so the
> sidecar does not double-enforce. The remaining engines (T3–T12) still run.

### Performance — loopback-hop overhead (benchmarked)

The sidecar adds one loopback HTTP hop plus the ArmorMiddleware buffer/replay.
Measured on an **Apple M5, Python 3.11, 3,000 iterations** via
`benchmarks/sidecar_overhead.py` (minimal guard, to isolate the hop from the
engine chain):

| Metric | Direct to upstream | Through sidecar | **Added by sidecar** |
|---|---|---|---|
| p50 | 239 µs | 632 µs | **~0.39 ms** |
| p90 | 262 µs | 701 µs | **~0.44 ms** |
| p99 | 373 µs | 864 µs | **~0.49 ms** |

To this hop cost, add the in-process engine-chain cost — **~0.11 ms p50 / ~0.15 ms
p99** for the full 10-engine request+response chain (`benchmarks/chain_overhead.py`,
same machine). So a fully-armored request through the sidecar costs on the order of
**~0.5 ms p50** over hitting the upstream directly. Re-measure on your own hardware
and workload before relying on any absolute figure.

### Security model and limitations

The sidecar treats the **upstream as untrusted** (that is why response-phase
engines exist). Concretely, the hop:

- proxies **POST with a non-empty body only** — MCP JSON-RPC over HTTP. Other
  methods (GET/SSE, DELETE) and empty bodies are refused (`405`/`400`) so a
  request the engines cannot meaningfully inspect never reaches the upstream. SSE
  streaming and HTTP session-DELETE are therefore not proxied.
- caps the buffered upstream response at `--max-response-bytes` (default 10 MiB)
  and never trusts the upstream's `Content-Length` — a compromised upstream cannot
  OOM the sidecar.
- is the **sole session authority**: `mcp-session-id` is never forwarded upstream
  and never accepted from an upstream response. The upstream must be **stateless
  with respect to MCP sessions** (armor mints/owns the session id; the upstream
  never issued the id the client carries).
- forces a canonical `Content-Type: application/json` on the forwarded request,
  strips client-supplied `X-Forwarded-*`, drops hop-by-hop and CRLF-bearing
  headers both ways, and does not store/re-inject cookies.
- Optionally pin the sidecar to one route with `--mcp-path /api/mcp`
  (`ARMOR_MCP_PATH`) so a client cannot reach other upstream paths through it.

Operational caveats to know before production:

- **Behind a load balancer**, `--host 0.0.0.0` and the injected `X-Forwarded-For`
  reflects the TCP peer (the LB), not the original client. The lean sidecar does
  not parse inbound `X-Forwarded-For`; if your upstream needs the true client IP,
  terminate XFF in your own middleware in front of the sidecar.
- **Multi-worker / horizontal scaling** inherits ArmorMiddleware's documented
  in-process session limitation: per-session T6/T10 state lives in the worker that
  opened the session. Run a single worker, or use sticky routing, until a shared
  session store lands (tracked separately).
- **Guard startup is fatal**: run with `lifespan="on"` (the shipped `main` does).
  If the guard cannot start (e.g. missing `ARMOR_SESSION_SECRET`), the server
  refuses to serve rather than forwarding unguarded.

### Other limitations

- **Extra network hop**: one loopback HTTP call per request (benchmarked above).
- **Separate process to deploy**: two processes/containers instead of one.
- **stdio transport is not covered** — see below.

#### stdio transport (not covered)

`ArmorMiddleware` is ASGI middleware: it sits inline on the **HTTP/JSON-RPC** path
and cannot intercept a stdio pipe. The sidecar therefore covers **HTTP transport
only** — this boundary is enforced (a non-HTTP ASGI scope raises
`NotImplementedError` rather than forwarding unguarded traffic) and tested
(`tests/adapters/test_sidecar.py::test_forwarding_app_refuses_non_http_scope`).

For a stdio-transport server, the options are:

1. **Switch to HTTP transport** for the deployment you want to protect (most
   production MCP servers use HTTP/SSE anyway).
2. **Use a native in-process integration** in your server's own language (see
   Option 2).

#### Bypass risk — network-isolate the upstream

The sidecar only protects traffic that goes *through* it. If a client can reach the
upstream (`:3000`) directly, it bypasses every engine. Bind the upstream to
loopback / a private network and ensure the sidecar is the only reachable path
(the Compose example above does this by not publishing the upstream port).

---

## Option 2 — Native TypeScript port (planned)

A `mcp-armor-ts` npm package would provide the same 12-engine architecture as a
native TypeScript/Node.js library — no sidecar, no extra deployment unit. It would
integrate as Express/Fastify middleware or a Hono plugin and use the same
`cosai.yaml` schema so policies are portable between Python and TypeScript.

This is not yet built. If you need it, open an issue at
[ragsvasan/mcp-armor](https://github.com/ragsvasan/mcp-armor/issues) — demand
signals prioritisation. In the meantime, Option 1 gives full CoSAI coverage for any
HTTP-transport server today.

---

## Questions

Open an issue or start a discussion at
[github.com/ragsvasan/mcp-armor](https://github.com/ragsvasan/mcp-armor).
