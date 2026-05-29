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

## vs. commercial agentic-AI platforms (CrowdStrike, et al.)

CrowdStrike's *"90-Day Roadmap for Securing Agentic AI"* whitepaper correctly identifies that T4 tool poisoning, T9 trust-boundary, and T12 audit failures live **inside the call path** — then sells the implementation as a closed Falcon module backed by an external agent you must trust and purchase.

mcp-armor *is* that in-call-path implementation, as OSS:

- **In-process, not a sidecar SOC.** mcp-armor runs inside the MCP server and sees tool responses and LLM re-feed before they leave the process. No external agent, no vendor trust anchor.
- **HMAC-signed tamper-evident audit (T12).** Not fire-and-forget logging — an HMAC-SHA256 chain (when `ARMOR_AUDIT_HMAC_KEY` is set) with DAG parent tracking and a sticky marker file that prevents silent downgrade. Detects both field tampering and log truncation. Forensics-ready without a separate SIEM contract.
- **Signed supply chain shipped, not aspirational (T6/T11).** Their roadmap *recommends* signed manifests; mcp-armor enforces Ed25519 registry signatures and blocks unsigned/typosquatted tools by default.
- **RE2-only, fail-closed.** Linear-time regex (no catastrophic backtracking DoS), frozen-dataclass immutability eliminating async context bleed — production-grade details closed platforms don't expose or guarantee.
- **`dry_run` mode for safe config tuning (NOT FOR PRODUCTION).** `CoSAIGuard(dry_run=True)` logs violations at WARNING and audits them without blocking, so you can tune policy thresholds before enabling enforcement. Auth errors always re-raise even in dry_run.

Roadmap (closing the remaining CrowdStrike workstreams as OSS controls): SIEM/SOAR emitter + anomaly thresholds (WS4), non-bypassable out-of-band human approval so an agent cannot resubmit its own confirmation token (WS7), and an incident-response containment orchestrator — pause tool / quarantine server / freeze session / revoke creds wired to engine exceptions (WS8). See [docs/VISION.md](docs/VISION.md#positioning-vs-commercial-platforms) for the full mapping.

## License

Apache 2.0
