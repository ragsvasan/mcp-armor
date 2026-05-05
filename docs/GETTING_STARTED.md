# mcp-armor — Getting Started

## Prerequisites

- Python 3.11+
- An MCP server built on FastMCP, FastAPI, or a custom JSON-RPC dispatcher

## Install

```bash
pip install mcp-armor

# FastAPI / ASGI support
pip install mcp-armor[fastapi]

# Development (tests, linting, type checking)
pip install mcp-armor[dev]
```

---

## 1. Zero-Config Start

The fastest path — sensible defaults, no config file:

```python
from mcp_armor import CoSAIGuard

guard = CoSAIGuard.default()
app = guard.wrap(your_app)
```

This enables all 12 engines with conservative defaults. In production, use a `cosai.yaml` config file so policy is explicit, auditable, and checked in to version control.

---

## 2. Config File

Copy the example config and edit it for your deployment:

```bash
cp cosai.yaml.example cosai.yaml
```

Then load it:

```python
guard = CoSAIGuard.from_config("cosai.yaml")
app = guard.wrap(your_app)
```

The config is validated at load time. Unknown keys are rejected. The engine fails to start rather than silently ignoring misconfiguration.

---

## 3. FastAPI Integration

```python
from fastapi import FastAPI
from mcp_armor import CoSAIGuard
from mcp_armor.adapters.fastapi import ArmorMiddleware

app = FastAPI()
guard = CoSAIGuard.from_config("cosai.yaml")

app.add_middleware(
    ArmorMiddleware,
    guard=guard,
    cors_origins=["https://app.example.com"],  # restrict cross-origin access (T7-001)
)

@app.on_event("startup")
async def startup():
    await guard.startup()

@app.on_event("shutdown")
async def shutdown():
    await guard.shutdown()
```

`guard.startup()` runs the startup-only checks (T8 network binding, T11 supply chain). It must be called before the server begins accepting requests. If either check fails, the exception propagates and the server does not start — fail-closed.

**`cors_origins`** — set this to the list of origins allowed to make cross-origin requests to the MCP endpoint (T7-001 / cosai-mcp T07-001). Omitting it (default `None`) emits a startup warning. Use `cors_origins=[]` to block all cross-origin requests. Never use `"*"` — a CORS wildcard on the MCP endpoint allows any web page to make credentialed requests on behalf of an authenticated user.

**Rate limiting and HTTP 429** — `ResourceExceededError` (raised by `ResourceEngine` when a session's call budget is exhausted) returns HTTP 429 with a `Retry-After: 60` header rather than a JSON-RPC 200 error, so HTTP-layer rate limiters and security scanners can detect it (T10-004 / cosai-mcp T10-004).

---

## 4. Raw JSON-RPC Dispatcher

For custom transports or stdio servers:

```python
from mcp_armor import CoSAIGuard
from mcp_armor.adapters.dispatcher import wrap_dispatcher

guard = CoSAIGuard.from_config("cosai.yaml")

async def my_dispatcher(request: dict) -> dict:
    # Your MCP handler logic
    ...

protected = wrap_dispatcher(my_dispatcher, guard)

# In your server loop:
response = await protected(incoming_request)
```

---

## 5. Per-Tool Policy

Override the guard's default policy for individual tools:

```python
@app.tool()
@guard.protect(
    threats=["T3", "T5"],
    pii_profile="hipaa",          # stricter PII for this tool only
)
async def patient_lookup(mrn: str) -> dict:
    ...

@app.tool()
@guard.protect(
    threats=["T2", "T3"],
    required_scope="admin",       # T2: reject callers without admin scope
)
async def admin_reset() -> str:
    ...
```

Per-tool decorators are additive — the guard wrapper handles session-level concerns (T1, T7, T12), the decorator handles tool-level policy (T2, T3, T5).

---

## 6. Handle Security Exceptions

All security violations raise typed `CoSAIException` subclasses. Framework adapters translate these to JSON-RPC error responses automatically. If you need custom handling:

```python
from mcp_armor.exceptions import (
    AuthenticationError,
    InjectionDetectedError,
    ResourceExceededError,
    CoSAIException,
)

try:
    result = await protected(request)
except AuthenticationError:
    # 401 — log, notify, rate-limit the caller
    ...
except InjectionDetectedError as e:
    # 400 — alert security team
    logger.critical("Injection attempt", finding=e.finding)
    ...
except ResourceExceededError:
    # 429 — caller exceeded budget
    ...
except CoSAIException:
    # 500 — catch-all for unexpected violations
    ...
```

---

## 7. Read the Audit Log

The T12 `AuditEngine` writes a hash-chained JSON Lines file. Verify chain integrity:

```python
from mcp_armor.engines.audit import AuditEngine

engine = AuditEngine(path="/var/log/mcp-armor/audit.jsonl")
engine._verify_chain()  # raises AuditChainError if tampered
```

Each line is a JSON object with `session_id`, `user_id`, `method`, `params_digest` (never raw params), and chain hash fields. Feed into any log aggregator (Splunk, CloudTrail, Datadog) using JSON Lines ingestion.

---

## 8. Pair with cosai-mcp Scanner

mcp-armor (server-side) and cosai-mcp (black-box scanner) cover complementary parts of the threat surface:

```bash
# In CI: scan for protocol-layer vulnerabilities
pip install cosai-mcp
cosai-mcp scan http://localhost:8000 --fail-on critical
```

The scanner detects T1/T3/T8/T10 failures from outside. mcp-armor enforces T4/T9/T12 (and optionally all 12) from inside. Together they provide complete coverage.

---

## Threat Coverage at a Glance

| What you get | Threat |
|---|---|
| Auth header check, JTI replay detection, DPoP binding | T1 |
| Per-tool scope enforcement, confused deputy prevention | T2 |
| JSON schema strict mode, injection guards, size limit | T3 |
| 18 injection patterns — tool definitions + response bodies | T4 |
| PII scrubbing (5 profiles: minimal / pci / hipaa / gdpr / strict) | T5 |
| Manifest hash + drift detection, typosquatting check | T6 |
| Session fixation prevention, cross-transport replay block | T7 |
| Bind address check, SSRF prevention | T8 |
| LLM output sanitization — 5-step pipeline | T9 |
| Call budget, wall-clock limit, loop depth, heartbeat | T10 |
| Tool allowlist, registry signature check | T11 |
| Hash-chained JSON Lines audit log, DAG tracing | T12 |

---

## Configuration Reference

See [cosai.yaml.example](../cosai.yaml.example) for the full annotated configuration. Key options:

| Key | Default | Description |
|---|---|---|
| `T1.require_dpop` | `true` | Require DPoP proof-of-possession on every request |
| `T2.default_policy` | `deny` | Deny tools not listed in `tool_policies` |
| `T3.max_payload_bytes` | `65536` | Maximum JSON-serialized params size |
| `T5.profile` | `pci` | PII detection profile |
| `T10.max_calls_per_session` | `100` | Hard cap on tool calls per session |
| `T10.max_wall_clock_secs` | `300` | Session time limit |
| `T12.path` | `/var/log/mcp-armor/audit.jsonl` | Audit log file path |

---

## Troubleshooting

**Server fails to start with `NetworkBindingError`**  
Your server is bound to `0.0.0.0`. Either change the bind address to `127.0.0.1`, or set `T8.allow_public_bind: true` in `cosai.yaml` (document the business reason for this override).

**All tool calls rejected with `AuthorizationError`**  
`T2.default_policy` is `deny` and no `tool_policies` are defined. Either add tool policies for each tool, or set `T2.default_policy: allow` (and accept the risk of no per-tool RBAC).

**`AuditChainError` on startup**  
The audit log chain is broken — either the file was truncated, lines were deleted, or the file was overwritten. Rotate to a new log file and investigate. Do not modify or delete the old file — it is evidence.

**`InjectionDetectedError` on legitimate tool responses**  
A legitimate tool response matched one of the 18 injection patterns. Review the specific pattern in `engines/boundary.py` and either: (a) sanitize the tool's response to remove the matching text, or (b) raise an issue if the pattern has a false positive — it may need tightening.
