# mcp-armor

Server-side protection middleware for MCP servers. Covers all 12 CoSAI threat categories (T1–T12) in a single composable library.

## Why

Every existing MCP security tool is either a scanner (runs *against* your server) or a document. mcp-armor runs *inside* your server — the only way to address threats that require being in the call path (T4 tool poisoning, T9 trust boundaries, T12 audit logging).

## Coverage Matrix

| Category | Threat | Engine | Layer |
|---|---|---|---|
| T1 | Improper Authentication | `AuthEngine` | Transport |
| T2 | Missing Access Control | `AuthzEngine` | Dispatch |
| T3 | Input Validation Failures | `ValidationEngine` | Dispatch |
| T4 | Data/Control Boundary | `BoundaryEngine` | Dispatch + Response |
| T5 | Inadequate Data Protection | `ProtectionEngine` | Response |
| T6 | Integrity/Verification | `IntegrityEngine` | Dispatch |
| T7 | Session Security Failures | `SessionEngine` | Transport |
| T8 | Network Binding Failures | `NetworkEngine` | Startup |
| T9 | Trust Boundary Failures | `TrustEngine` | Response |
| T10 | Resource Management | `ResourceEngine` | Dispatch + Response |
| T11 | Supply Chain/Lifecycle | `SupplyChainEngine` | Startup |
| T12 | Insufficient Logging | `AuditEngine` | All (wraps chain) |

## Install

```bash
pip install mcp-armor

# With FastAPI/ASGI support
pip install mcp-armor[fastapi]

# With FastMCP support
pip install mcp-armor[fastmcp]
```

## Quick Start

**FastMCP:**
```python
from fastmcp import FastMCP
from mcp_armor import CoSAIGuard
from mcp_armor.adapters.fastmcp import wrap_fastmcp

app = FastMCP("my-server")
guard = CoSAIGuard.from_config("cosai.yaml")
protected = wrap_fastmcp(app, guard)

@app.tool()
async def echo(message: str) -> str:
    return f"Echo: {message}"
```

**FastAPI / ASGI:**
```python
from fastapi import FastAPI
from mcp_armor import CoSAIGuard
from mcp_armor.adapters.fastapi import ArmorMiddleware

inner = FastAPI()
guard = CoSAIGuard.from_config("cosai.yaml")
app = ArmorMiddleware(
    inner,
    guard,
    cors_origins=["https://app.example.com"],  # required for CORS enforcement (T7-001)
)
```

**Raw JSON-RPC dispatcher:**
```python
from mcp_armor import CoSAIGuard
from mcp_armor.adapters.dispatcher import wrap_dispatcher

guard = CoSAIGuard.from_config("cosai.yaml")
protected = wrap_dispatcher(my_dispatcher, guard)
response = await protected({"method": "tools/call", "params": {...}})
```

See [cosai.yaml.example](cosai.yaml.example) for the full configuration reference and [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) for a step-by-step guide.

## Using mcp-armor with TypeScript / non-Python servers

mcp-armor is a Python library and cannot be imported into a TypeScript or Node.js project directly. If your MCP server is written in TypeScript (or any other language), run mcp-armor as a **sidecar proxy** — it sits in front of your server, enforces all 12 CoSAI controls on every request, and forwards clean traffic to your server over HTTP.

```
MCP Client → mcp-armor sidecar (Python, :8000) → Your TS server (:3000)
```

See [docs/TYPESCRIPT.md](docs/TYPESCRIPT.md) for the full setup guide, Docker Compose example, and notes on a future native TypeScript port.

## Design

See [docs/DESIGN.md](docs/DESIGN.md) for the full architecture, three-layer call path model, and design decisions.

## Relation to cosai-mcp

[cosai-mcp](https://github.com/cosai-oasis/cosai-mcp) is the black-box scanner — it probes your server from the outside. mcp-armor is the server-side SDK — it runs inside your server. They are complementary: use the scanner in CI to detect protocol-level failures, use mcp-armor at runtime for defence.

## License

Apache 2.0
