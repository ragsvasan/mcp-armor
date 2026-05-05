# mcp-armor — Architecture

## Overview

mcp-armor is a server-side protection library. It runs *inside* the target MCP server, in the request call path, providing the defence mechanisms that black-box scanners cannot reach. It is not an MCP server, not a proxy, and not a scanner.

---

## Three-Layer Call Path Model

Every MCP server has three natural integration points. Each CoSAI threat category belongs to exactly one — this is not a stylistic choice, it reflects where in the call path the threat manifests and where the defence must be applied.

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
      │  ← tool handler executes here →
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

**Critical constraint:** T4, T9, T12 require being in the call path. No black-box probe can observe whether a tool response contains prompt injection, whether LLM output is sanitized before re-feed, or whether execution is logged. mcp-armor is the only mechanism for these three categories.

---

## CoSAIGuard — The Composition Class

`CoSAIGuard` assembles engines into a fixed-order chain and drives all lifecycle hooks. Server authors interact with the guard, not individual engines.

```
CoSAIGuard
  │
  ├── engines: list[ProtectionEngine]  (ordered — never rearranged)
  │
  ├── startup()        → calls on_startup() for each engine (T8, T11 fail here)
  ├── open_session()   → calls on_session_start() for each engine in order
  ├── _run_request()   → calls on_request() for each engine in order
  ├── _run_response()  → calls on_response() in REVERSE order (response chain)
  ├── close_session()  → calls on_session_end() for each engine
  └── shutdown()       → calls on_shutdown() for each engine
```

**Request chain order** (fixed):
`audit → auth → session → network → supply_chain → authz → validation → boundary → resources → integrity`

**Response chain order** (reversed):
`integrity → resources → boundary → protection → trust → audit`

The reversal is intentional: audit wraps everything (first in, last out). Protection (PII scrubbing) and trust (LLM sanitization) run on responses only and belong nearest the response exit point.

---

## Session Context

All state shared between engines flows through `CoSAIContext` — a frozen dataclass stored in an async-safe `contextvars.ContextVar`. No global mutable state.

```python
@dataclass(frozen=True)
class CoSAIContext:
    session_id:          str
    user_id:             str | None        # set by AuthEngine after token validation
    tenant_id:           str | None        # for multi-tenant isolation
    tool_manifest_hash:  str               # T6: SHA-256 of tools/list at session open
    budget:              BudgetState       # T10: calls_used, wall_clock_start, loop_depth
    audit_parent_id:     str | None        # T12: DAG parent for nested calls
    findings:            tuple[Finding]    # accumulated — immutable append
```

Engines never mutate context. They return a new context via `dataclasses.replace()`. The guard replaces the ContextVar value after each engine.

---

## ProtectionEngine Protocol

Every engine implements the same six lifecycle hooks:

```python
class ProtectionEngine(Protocol):
    async def on_startup(self) -> None: ...
    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext: ...
    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext: ...
    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext: ...
    async def on_session_end(self, ctx: CoSAIContext) -> None: ...
    async def on_shutdown(self) -> None: ...
```

Engines that only apply at one layer simply `return ctx` in the other hooks. `on_startup` is the only hook where startup-only engines (T8, T11) do meaningful work.

Custom engines: implement `ProtectionEngine`, pass to `CoSAIGuard([..., MyEngine()])`. The guard does not care where the engine came from.

---

## Engine Responsibility Map

| Engine | File | Threat(s) | Active Layer(s) |
|--------|------|-----------|-----------------|
| `AuditEngine` | `engines/audit.py` | T12 | 1 open, 2 request, 3 response, 1 close |
| `AuthEngine` | `engines/auth.py` | T1 | 1 (every request) |
| `SessionEngine` | `engines/session.py` | T7 | 1 |
| `NetworkEngine` | `engines/network.py` | T8 | startup (bind check) + 2 (SSRF in tool args) |
| `SupplyChainEngine` | `engines/supply_chain.py` | T11 | startup (register) + 2 (tool call) + 3 (tools/list response) |
| `AuthzEngine` | `engines/authz.py` | T2 | 2 + `filter_tools_list` (tools/list scope filter) |
| `ValidationEngine` | `engines/validation.py` | T3 | 2 |
| `BoundaryEngine` | `engines/boundary.py` | T4 | 2 (request) + 3 (response) |
| `ResourceEngine` | `engines/resources.py` | T10 | 2 + 3 |
| `IntegrityEngine` | `engines/integrity.py` | T6 | 2 |
| `ProtectionEngine` | `engines/protection.py` | T5 | 3 |
| `TrustEngine` | `engines/trust.py` | T9 | 3 |

---

## Exception Hierarchy

All engines raise typed `CoSAIException` subclasses. Framework adapters translate to HTTP status codes and JSON-RPC error codes at the boundary — never inside engine logic.

```
CoSAIException
├── AuthenticationError      T1  → 401  / -32001
├── AuthorizationError       T2  → 403  / -32002
├── ValidationError          T3  → 400  / -32602
├── InjectionDetectedError   T4  → 400  / -32003
├── PIILeakError             T5  → 500  / -32004
├── IntegrityError           T6  → 500  / -32005
├── SessionError             T7  → 401  / -32006
├── NetworkBindingError      T8  → startup / -32008 (also raised at request time for SSRF)
├── TrustBoundaryViolation   T9  → 500  / -32007
├── ResourceExceededError    T10 → 429  / -32010
├── SupplyChainError         T11 → startup / -32011 (also raised at request + response time)
└── AuditChainError          T12 → 500  / -32009
```

`NetworkBindingError` and `SupplyChainError` are raised at startup for misconfigured bind
addresses and invalid tool allowlists respectively — preventing the server from starting in
an insecure state. They are also raised at request time: `NetworkEngine` checks every
`tools/call` argument for SSRF targets; `SupplyChainEngine` validates the tool name on
every `tools/call` and re-validates the full manifest on every `tools/list` response.

---

## Framework Adapters

Adapters translate between the framework's request/response objects and `MCPRequest`/`MCPResponse`. The engines are adapter-agnostic.

```
mcp_armor/adapters/
  fastmcp.py      wrap_fastmcp(app, guard) → protected FastMCP app
  fastapi.py      ArmorMiddleware(app, guard) → ASGI middleware
  dispatcher.py   wrap_dispatcher(fn, guard) → async callable
```

**ArmorMiddleware (ASGI):** intercepts the raw HTTP body, parses JSON-RPC, runs the request chain, replays the body to the downstream app, captures the response, runs the response chain. Compatible with FastAPI, Starlette, and any other ASGI-compliant framework.

**wrap_dispatcher:** the lowest-level integration. Wraps any `async (dict) -> dict` function. Useful for custom transports, stdio servers, and testing.

**wrap_fastmcp:** wraps a `fastmcp.FastMCP` instance. Validates the type at call time,
hooks into tool dispatch via `_GuardedToolDispatcher`, and guarantees `close_session` fires
in a `finally` block even when the tool raises.

---

## Module Map

```
mcp_armor/
  __init__.py          Public API: CoSAIGuard, CoSAIContext, all exceptions
  guard.py             CoSAIGuard: assembly, lifecycle, framework integration
  context.py           CoSAIContext dataclass + ContextVar
  types.py             MCPRequest, MCPResponse, Finding, BudgetState, enums
  exceptions.py        CoSAIException hierarchy + JSON-RPC error helpers

  engines/
    base.py            ProtectionEngine Protocol (runtime_checkable)
    auth.py            T1: bearer token + DPoP validation
    authz.py           T2: per-tool RBAC, confused deputy prevention
    validation.py      T3: JSON schema strict mode + injection guards
    boundary.py        T4: 24 injection patterns, request + response scan (incl. manifest descriptions)
    protection.py      T5: PII scrubbing (5 RE2-based profiles)
    integrity.py       T6: SHA-256 manifest hash + drift detection
    session.py         T7: session binding, fixation prevention
    network.py         T8: bind address check + SSRF prevention
    trust.py           T9: 5-step LLM output sanitizer
    resources.py       T10: call budget, wall-clock, loop depth
    supply_chain.py    T11: tool allowlist + registry sig check
    audit.py           T12: hash-chained JSON Lines append log

  adapters/
    fastmcp.py         FastMCP wrapper (stub — pending stable API)
    fastapi.py         ASGI middleware (implemented)
    dispatcher.py      Raw JSON-RPC wrapper (implemented)
```

---

## Immutability Contract

All public types are frozen dataclasses with these invariants:

- `tuple` for all list-valued fields in frozen dataclasses
- `MappingProxyType` for all dict-valued fields in frozen dataclasses
- `BudgetState.increment()` / `.descend()` return new instances — never mutate
- `CoSAIContext.with_*()` methods use `dataclasses.replace()` — never mutate
- `MCPResponse.raw_body` is HTML-escaped **at ingestion** (`html.escape(quote=True)`) — not at render time

This eliminates a class of bugs where mutable containers leak across async task boundaries or between probes.

---

## RE2 Discipline

All regex-based detection (T4, T5, T9) uses `google-re2` (linear time, no backtracking). Catastrophic backtracking on attacker-controlled input is a DoS vector.

Import fallback: if `re2` is not installed, the library falls back to stdlib `re` with a warning. This is acceptable for development. Production deployments should have `google-re2` installed. As an additional defence-in-depth measure, `BoundaryEngine._scan()` truncates strings to `_MAX_SCAN_LEN` (8,192 chars) before pattern matching — injection phrases are short, so this creates no detection gap while bounding worst-case regex time.

Pattern validation: all patterns are compiled at engine construction time. A pattern that `re2` rejects raises `UnsafePatternError` at startup — not at runtime.

---

## Audit Log Format

The T12 `AuditEngine` writes a hash-chained JSON Lines file:

```json
{"ts": 1714176000.0, "entry_id": "uuid4", "parent_id": null, "session_id": "s1",
 "user_id": "user@example.com", "tenant_id": null,
 "event": "session_start", "method": "", "params_digest": "",
 "prev_hash": "0000...0000", "chain_hash": "sha256:abcd..."}

{"ts": 1714176001.2, "entry_id": "uuid4", "parent_id": "prev-entry-id", "session_id": "s1",
 "event": "request", "method": "tools/call", "params_digest": "sha256:efgh...",
 "prev_hash": "sha256:abcd...", "chain_hash": "sha256:ijkl..."}
```

- `params_digest`: SHA-256 of raw params — never raw values (no PII in logs)
- `parent_id`: enables DAG reconstruction for concurrent/nested calls
- `chain_hash = SHA-256(prev_hash + entry_id)` — tampering breaks the chain at the next entry
- `verify_chain()` walks the file and raises `AuditChainError` at the first broken link
