# CoSAI Server-Side SDK — Design Document

**Date:** 2026-04-28 (updated 2026-05-28)  
**Status:** Implemented — v0.2.0  
**Context:** This document captures the design rationale for mcp-armor, a server-side
protection library covering all 12 CoSAI threat categories.

---

## What This Is (and Is Not)

The existing `cosai_mcp/` codebase is a **scanner** — it probes *other* MCP servers from the
outside. This document proposes the **inverse**: a library that an MCP server *author* drops
in to protect their own server at runtime.

| What exists | What this proposes |
|---|---|
| `cosai_mcp/` — black-box prober, probe harness, detection middleware | A **server-side SDK** — protection middleware any MCP server imports and uses |
| Runs *against* target servers | Runs *inside* the protected server |
| We control the execution context | Server author controls the execution context |

The existing middleware files (`auth.py`, `boundary.py`, etc.) already contain the right
internals. What they lack is the **composition layer** that ties them into a server framework.

---

## The Three-Layer Call Path Model

Every MCP server has three distinct integration points. Each CoSAI threat class belongs to
exactly one layer — this is not a stylistic choice, it reflects where in the call path the
threat manifests and where the defence must be applied.

```
CLIENT REQUEST
      │
   ┌──▼────────────────────────────────────────┐
   │  Layer 1 — Transport / Session             │
   │                                            │
   │  T1  Improper Authentication               │
   │  T7  Session Security Failures             │
   │  T8  Network Binding Failures (startup)    │
   │  T11 Supply Chain (startup, tool load)     │
   │  T12 Audit chain opens here                │
   └──┬─────────────────────────────────────────┘
      │
   ┌──▼────────────────────────────────────────┐
   │  Layer 2 — Tool Dispatch                   │
   │                                            │
   │  T2  Missing Access Control (per-tool)     │
   │  T3  Input Validation (schema + injection) │
   │  T4  Definition scan (tool poisoning)      │
   │  T6  Manifest drift detection              │
   │  T10 Per-call budget enforcement           │
   └──┬─────────────────────────────────────────┘
      │
      │  (tool handler executes here)
      │
   ┌──▼────────────────────────────────────────┐
   │  Layer 3 — Response / Re-Feed              │
   │                                            │
   │  T4  Response injection scan               │
   │  T5  PII scrubbing before response         │
   │  T9  LLM output sanitization               │
   │  T10 Loop detection, wall-clock close      │
   │  T12 Audit chain closes here               │
   └──┬─────────────────────────────────────────┘
      │
CLIENT RESPONSE
```

**Critical note on T4, T9, T12:** these three threats cannot be addressed by a black-box
prober — they require being in the call path. The server-side library is the *only* viable
defence mechanism for them. This is the three-engine architecture verdict from the P7 panel.

---

## Session Context Carrier

Every layer reads from and writes to a single `CoSAIContext` — an async-safe
`contextvars.ContextVar` so each async handler gets its own isolated copy. No global mutable
state.

```python
@dataclass(frozen=True)
class CoSAIContext:
    session_id:          str
    user_id:             str | None
    tenant_id:           str | None
    tool_manifest_hash:  str               # T6 baseline — set at initialize
    budget:              BudgetState       # T10 — mutable via replace()
    audit_parent_id:     str | None        # T12 DAG parent
    loop_depth:          int               # T10 loop detection
    findings:            tuple[Finding, ...]  # accumulated, immutable append
```

`BudgetState` is the one field that needs mutation during a session. It is replaced (not
mutated) via `dataclasses.replace()` to preserve the frozen invariant.

---

## The API Surface

Two integration styles that coexist cleanly.

### A — Framework Wrapper (low-friction adoption)

```python
from cosai_server import CoSAIGuard

guard = CoSAIGuard.from_config("cosai.yaml")

# FastMCP
app = guard.wrap(fastmcp_app)

# FastAPI / ASGI
app = guard.asgi(fastapi_app)

# Raw JSON-RPC dispatcher
dispatcher = guard.wrap_dispatcher(my_dispatcher)
```

The wrapper handles all cross-cutting concerns: T1 (auth on every request), T7 (session
binding), T8 (bind address check at startup), T12 (audit opens/closes per call).

### B — Per-Tool Decorator (fine-grained policy)

```python
@app.tool()
@guard.protect(
    threats=["T3", "T5"],
    budget_override=BudgetPolicy(max_calls=5),
    pii_profile="strict",
    input_schema=QueryInput,          # T3 strict schema
)
async def query_db(sql: str) -> str:
    ...

@app.tool()
@guard.protect(
    threats=["T2", "T3"],
    required_scope="admin",           # T2 — per-tool RBAC
)
async def admin_reset() -> str:
    ...
```

The framework wrapper and per-tool decorators are additive — the wrapper handles the session
layer, decorators handle tool-specific policy. Neither is required without the other.

---

## Policy-as-Code Configuration

```yaml
# cosai.yaml
version: 1

threats:
  T1:
    enabled: true
    require_dpop: true
    jti_cache_size: 10000
    token_expiry_max_secs: 3600

  T2:
    enabled: true
    default_policy: deny              # fail-closed — unlisted tools are denied
    destructive_token_ttl_seconds: 60 # confirmation token lifetime for two-stage commit
    tool_policies:
      query_db:   [read:public]
      admin_reset: [admin]
      delete_resource:                # destructive tool — two-stage commit enforced
        required_scopes: [admin]
        destructive: true             # any call without confirm_token → AuthorizationError

  T3:
    enabled: true
    max_payload_bytes: 65536
    strict_schema: true               # unknown fields rejected, not ignored
    injection_patterns: builtin       # or path to custom pattern file

  T4:
    enabled: true
    scan_definitions: true            # scan tool defs at initialize + on drift
    scan_responses: true              # scan every tool response body

  T5:
    enabled: true
    profile: pci                      # preset: pci | hipaa | gdpr | minimal
    custom_patterns: []               # additional RE2 patterns

  T6:
    enabled: true
    baseline_on_initialize: true      # snapshot tool manifest at session start
    fail_on_drift: true               # abort session if manifest changes

  T7:
    enabled: true
    bind_session_to_dpop: true

  T8:
    enabled: true
    allow_public_bind: false          # 0.0.0.0 → error at startup
    block_rfc1918: true               # SSRF guard via tools

  T9:
    enabled: true
    max_output_length: 32768
    strip_injection_patterns: true

  T10:
    enabled: true
    max_calls_per_session: 100
    max_wall_clock_secs: 300
    loop_depth_limit: 10
    heartbeat_interval_secs: 30

  T11:
    enabled: true
    tool_allowlist: []                # empty = deny all unlisted tools
    require_registry_signature: false # true = only signed tools from registry

  T12:
    enabled: true
    sink: jsonl                       # jsonl | cloudtrail | splunk | stdout
    path: /var/log/cosai/audit.jsonl
    log_params_as_digest: true        # SHA-256 of params, never raw values
    chain_verify_on_startup: true
```

The config loader validates against a JSON schema and constructs typed, frozen policy objects.
Unknown keys are rejected (same discipline as the threat catalog).

---

## Exception Hierarchy (Fail-Closed Contract)

All exceptions inherit from `CoSAIException`. Framework adapters translate to HTTP status
codes and JSON-RPC error codes at the boundary — never inside the security logic itself.

```
CoSAIException
├── AuthenticationError          T1   → HTTP 401  / JSON-RPC -32001
├── AuthorizationError           T2   → HTTP 403  / JSON-RPC -32002
├── ValidationError              T3   → HTTP 400  / JSON-RPC -32602
├── InjectionDetectedError       T4   → HTTP 400  / JSON-RPC -32003
├── PIILeakError                 T5   → HTTP 500  / JSON-RPC -32004
├── IntegrityError               T6   → HTTP 500  / JSON-RPC -32005
├── SessionError                 T7   → HTTP 401  / JSON-RPC -32006
├── NetworkBindingError          T8   → startup only — raises at server init
├── TrustBoundaryViolation       T9   → HTTP 500  / JSON-RPC -32007
├── ResourceExceededError        T10  → HTTP 429  / JSON-RPC -32008
├── SupplyChainError             T11  → startup only — raises at server init
└── AuditChainError              T12  → HTTP 500  / JSON-RPC -32009
```

The startup-only exceptions (T8, T11) are designed to prevent the server from starting in an
insecure configuration — fail-closed at the process level, not the request level.

---

## Component Responsibility Map

| Component | File | Threat(s) | Layer |
|---|---|---|---|
| `CoSAIGuard` | `guard.py` | (composition) | all |
| `CoSAIContext` | `context.py` | (shared state) | all |
| `AuthEngine` | `engines/auth.py` | T1, T7 | 1 |
| `SessionEngine` | `engines/session.py` | T7 | 1 |
| `NetworkEngine` | `engines/network.py` | T8 | 1 (startup) |
| `SupplyChainEngine` | `engines/supply_chain.py` | T11 | 1 (startup) |
| `AuthzEngine` | `engines/authz.py` | T2 | 2 |
| `ValidationEngine` | `engines/validation.py` | T3 | 2 |
| `BoundaryEngine` | `engines/boundary.py` | T4 | 2 + 3 |
| `IntegrityEngine` | `engines/integrity.py` | T6 | 2 |
| `ResourceEngine` | `engines/resources.py` | T10 | 2 + 3 |
| `PIIEngine` | `engines/protection.py` | T5 | 3 |
| `TrustEngine` | `engines/trust.py` | T9 | 3 |
| `AuditEngine` | `engines/audit.py` | T12 | 1 + 3 (wraps all) |

Each engine implements the `ProtectionEngine` protocol:

```python
class ProtectionEngine(Protocol):
    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext: ...
    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext: ...
    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext: ...
    async def on_session_end(self, ctx: CoSAIContext) -> None: ...
```

`CoSAIGuard` assembles the chain in the correct order and drives each hook.

---

## Design Principles (v0.2.0 additions)

**Async-safe audit writes.** All audit I/O is dispatched via `asyncio.to_thread`. An
`asyncio.Lock` wraps seq-assignment and the disk write as one atomic unit — the event
loop is never blocked and concurrent coroutines cannot produce duplicate `prev_hash`
values.

**`dry_run` is explicitly NOT FOR PRODUCTION.** The `dry_run` mode exists solely for
configuration tuning in non-production environments. When active, all security
violations are logged at WARNING and audited as `"dry_run_violation"` events, but no
request is blocked (except auth errors — those always re-raise). Both the guard
constructor and the config loader log a WARNING when dry_run is activated. The flag
name and all docs emphasize: NOT FOR PRODUCTION.

**HMAC audit chain integrity is the default production posture.** Pure SHA-256 chaining
detects field tampering but not log truncation followed by chain recalculation. Setting
`ARMOR_AUDIT_HMAC_KEY` closes this gap. The `.hmac_enabled` sticky marker prevents a
subsequent deployment from silently downgrading integrity by omitting the key. This
makes HMAC enforcement sticky — once enabled, it cannot be removed accidentally.

---

## Design Choice: Option B (Composable Primitives + Thin Adapters)

**Chosen approach:** the library exposes composable primitives as the core product. Framework
adapters (FastMCP, FastAPI, ASGI, raw dispatcher) are thin wrappers that translate between
the framework's request/response model and `MCPRequest`/`MCPResponse`.

**Why not Option A (library owns the JSON-RPC layer):**
- Brittle to framework internals changes
- Harder to test individual engines in isolation
- Harder for server authors to customise one layer without touching others

**What Option B gives us:**
- Each engine is independently testable
- Server authors can use `guard.wrap()` for zero-config adoption or wire engines manually
  for custom pipelines
- Adding a new framework adapter is ~50 lines, not a fork
- The primitives are the security guarantee; the adapters are convenience

---

## Implementation Status

All components described in this document are implemented in v0.1.0. See
[COVERAGE.md](COVERAGE.md) for the full sub-threat coverage matrix and test references.
