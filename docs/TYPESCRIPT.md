# Using mcp-armor with TypeScript (and other non-Python) MCP servers

mcp-armor is a Python library. It cannot be `npm install`-ed into a TypeScript
project. This guide covers the two paths available to TypeScript MCP server authors.

---

## Option 1 — Sidecar proxy (available today)

Run mcp-armor as a thin Python process in front of your existing server.
`ArmorMiddleware` enforces all 12 CoSAI controls on every JSON-RPC request and
forwards clean traffic to your server over HTTP. Your TypeScript server never
sees an unvalidated request.

```
MCP Client ──► mcp-armor sidecar  ──► Your TypeScript server
               (Python, :8000)         (Node.js, :3000)
               all 12 engines run      only sees clean requests
```

### Minimal sidecar — `proxy_server.py`

```python
import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from mcp_armor import CoSAIGuard
from mcp_armor.adapters.fastapi import ArmorMiddleware

UPSTREAM = "http://localhost:3000"

inner = FastAPI()
guard = CoSAIGuard.from_config("cosai.yaml")
app = ArmorMiddleware(inner, guard)


@inner.post("/")
async def forward(request: Request) -> JSONResponse:
    body = await request.body()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            UPSTREAM,
            content=body,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
    return JSONResponse(content=resp.json(), status_code=resp.status_code)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
```

### Install and run

```bash
pip install "mcp-armor[fastapi]" httpx uvicorn
cp cosai.yaml.example cosai.yaml   # edit for your deployment
python proxy_server.py
```

Point your MCP client at `:8000`. Your TypeScript server continues to run on
`:3000` and is not exposed directly.

### Docker Compose example

```yaml
services:
  mcp-armor:
    image: python:3.12-slim
    working_dir: /app
    volumes:
      - ./proxy_server.py:/app/proxy_server.py
      - ./cosai.yaml:/app/cosai.yaml
    command: >
      sh -c "pip install 'mcp-armor[fastapi]' httpx uvicorn &&
             python proxy_server.py"
    ports:
      - "8000:8000"
    depends_on:
      - mcp-ts

  mcp-ts:
    build: .          # your existing TypeScript Dockerfile
    expose:
      - "3000"
    environment:
      - NODE_ENV=production
```

The TypeScript container is not published to the host — only the sidecar is.

### What the proxy covers

Every CoSAI control runs at the sidecar layer:

| Control | Where it fires |
|---|---|
| T1 Auth / DPoP | Before request reaches TS server |
| T2 RBAC / destructive gate | Before request reaches TS server |
| T3 Input validation | Before request reaches TS server |
| T4 Prompt injection | Both request args and TS server response |
| T5 PII scrubbing | On response from TS server |
| T6 Tool manifest integrity | At sidecar startup |
| T7 Session fixation | Before request reaches TS server |
| T8 SSRF / network binding | At sidecar startup |
| T9 LLM output sanitization | On response from TS server |
| T10 Resource budgets | Per session in sidecar |
| T11 Supply chain | At sidecar startup |
| T12 Audit log | Every request + response, in sidecar |

### Limitations of the proxy approach

- **Extra network hop**: one additional loopback HTTP call per request. In
  practice this is sub-millisecond on the same host or in the same pod.
- **Separate process to deploy**: you manage two processes (or containers)
  instead of one.
- **stdio transport**: the proxy only covers HTTP transport. If your TypeScript
  server uses stdio (e.g. for local Claude Desktop integration), the sidecar
  cannot intercept that traffic. See the stdio note below.

#### stdio transport

mcp-armor's `ArmorMiddleware` is an HTTP/ASGI middleware — it cannot sit inline
on a stdio pipe. For stdio-transport TypeScript servers, the options are:

1. **Switch to HTTP transport** for the deployment you want to protect (most
   production MCP servers use HTTP/SSE anyway).
2. **Use a TypeScript port** (see Option 2 below) — a native TS library can hook
   directly into the stdio message loop.

---

## Option 2 — Native TypeScript port (planned)

A `mcp-armor-ts` npm package would provide the same 12-engine architecture as a
native TypeScript/Node.js library — no sidecar, no extra deployment unit. It
would integrate as Express/Fastify middleware or a Hono plugin, and use the same
`cosai.yaml` config schema so policies are portable between Python and TypeScript
deployments.

This is not yet built. If you need it, please open an issue at
[ragsvasan/mcp-armor](https://github.com/ragsvasan/mcp-armor/issues) — demand
signals prioritisation.

In the meantime, Option 1 (sidecar proxy) gives full CoSAI coverage for any
HTTP-transport TypeScript MCP server today.

---

## Questions

Open an issue or start a discussion at
[github.com/ragsvasan/mcp-armor](https://github.com/ragsvasan/mcp-armor).
