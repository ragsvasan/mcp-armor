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

**Zero-config (sensible defaults):**
```python
from mcp_armor import CoSAIGuard

guard = CoSAIGuard.default()
app = guard.wrap(your_fastmcp_or_asgi_app)
```

**From config file:**
```python
guard = CoSAIGuard.from_config("cosai.yaml")
app = guard.wrap(app)
```

**Per-tool decorator:**
```python
@app.tool()
@guard.protect(threats=["T3", "T5"], pii_profile="strict")
async def query_db(sql: str) -> str:
    ...
```

**Raw JSON-RPC dispatcher:**
```python
protected = guard.wrap_dispatcher(my_dispatcher)
response = await protected({"method": "tools/call", "params": {...}})
```

See [cosai.yaml.example](cosai.yaml.example) for the full configuration reference.

## Design

See [docs/DESIGN.md](docs/DESIGN.md) for the full architecture, three-layer call path model, and design decisions.

## Relation to cosai-mcp

[cosai-mcp](https://github.com/cosai-oasis/cosai-mcp) is the black-box scanner — it probes your server from the outside. mcp-armor is the server-side SDK — it runs inside your server. They are complementary: use the scanner in CI to detect protocol-level failures, use mcp-armor at runtime for defence.

## License

Apache 2.0
