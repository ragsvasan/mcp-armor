# mcp-armor — Implementation Workplan

**Date:** 2026-04-27  
**Status:** Scaffold complete. Core engines stubbed. Ready to implement.

---

## How to read this document

- **→** means "depends on" (sequential)
- **‖** means "can run in parallel"
- **[T1]** / **[T2]** = panel tier per global CLAUDE.md rules
- Every phase ends with: panel → fix → tests green → commit

---

## Dependency Graph

```
P0: Scaffold ✓
  │
  ├── P1: Core Engine Implementations (T1, T3, T4, T5, T9, T10)
  ‖
  ├── P2: Guard + Context + Config loader
        ↓ (both complete)
      P3: Adapter Implementations (ASGI, dispatcher)
        │
        ├── P4: Stub Completions (T2, T6, T7, T11)
        ‖
        ├── P5: FastMCP Adapter
        │     ↓
        └── P6: Test Suite
              ↓
            P7: CI/CD + PyPI
              ↓
            P8: Examples + Docs polish
```

P1 ‖ P2 → P3 → (P4 ‖ P5) → P6 → P7 → P8

---

## Phase 0 — Scaffold ✓ COMPLETE

**What:** Project structure, pyproject.toml, all module stubs, ProtectionEngine protocol, guard assembly, exceptions, types, context.

**Delivered:**
- `mcp_armor/` package with all 12 engine stubs
- `CoSAIGuard.from_config()` and `CoSAIGuard.default()`
- `CoSAIContext` ContextVar
- Full exception hierarchy with JSON-RPC codes
- `ArmorMiddleware` (ASGI) and `wrap_dispatcher` adapters
- `cosai.yaml.example`
- Full docs suite

**Panel:** T3 (scaffold — no auth/db logic)

---

## Phase 1 — Core Engine Implementations

**What:** Fill the five highest-value engine stubs with working logic. These are the engines where "stub with NotImplementedError" is not acceptable for any production use.

**Scope:**

### P1a — T4 BoundaryEngine (already partially done)
- Complete `on_session_start`: scan `tools/list` result for injection in tool definitions
- Add `scan_tool_manifest(tools: list[dict]) -> list[Finding]` public method
- Called by guard after `tools/list` at session open — not just per-call
- **Panel: T2** (RE2 patterns, content scan — no auth path)

### P1b — T1 AuthEngine
- JWT signature validation (`joserfc`)
- JTI replay cache (LRU `OrderedDict`, thread-safe)
- Token expiry enforcement
- Session ID binding: token `sub` must match `ctx.session_id`
- DPoP proof validation (RFC 9449) — Ed25519 + ES256
- **Panel: T1** (new auth logic)

### P1c — T3 ValidationEngine
- JSON schema strict mode via `jsonschema` — validate `params.arguments` against discovered `inputSchema`
- Injection guard: RE2 scan of string-valued arguments for command injection, path traversal, SQL injection
- Size limit: `len(json.dumps(params).encode()) > max_payload_bytes`
- Schema cache: `{tool_name: compiled_schema}` — populated from `tools/list` at session open
- **Panel: T2** (input validation — no auth path)

### P1d — T9 TrustEngine (already partially done)
- Fix `strip_injections` typo in `__init__` (currently `strip_injections` is used but arg is `strip_injection_patterns`)
- Add public `sanitize(text: str) -> str` method (already done — verify it's called correctly by adapters)
- **Panel: T3**

### P1e — T10 ResourceEngine (already partially done)
- Complete wall-clock check (already done)
- Add `descend()` / `ascend()` calls for loop depth tracking — guard must call `ctx.budget.descend()` when a tool calls another tool
- HeartbeatMonitor: background thread that marks sessions as dead after `heartbeat_interval_secs` without a `progress` notification
- **Panel: T2**

**Dependencies:** none (all engines are independent)  
**Delivers:** 5 working engines with full test coverage  
**Panel gate:** T2 for P1a/P1c/P1e, T1 for P1b

---

## Phase 2 — Guard + Context + Config Loader

**What:** Wire the guard assembly properly and build the config loader from `cosai.yaml`.

**Scope:**
- `config.py`: typed frozen `PolicyConfig` dataclasses — one per threat category
- `CoSAIGuard.from_config()`: replace inline dict access with typed policy objects
- `CoSAIGuard._run_request()` / `_run_response()`: add error handling that catches `CoSAIException` and routes to the appropriate adapter error format
- `CoSAIContext` propagation: guard sets ContextVar before and after each engine hook
- Config schema validation: `cosai.yaml` validated against a JSON schema at load time — unknown keys rejected
- `CoSAIGuard.startup()` must be called from the framework adapter's lifespan handler (document this explicitly)

**Panel gate:** T2

---

## Phase 3 — Adapter Implementations

**Depends on:** P1, P2

**What:** Make the ASGI middleware and dispatcher wrapper production-ready.

**Scope:**

### P3a — ArmorMiddleware (ASGI)
- Handle session lifecycle properly: `open_session()` on `initialize`, `close_session()` on session disconnect
- Extract `session_id` from `Mcp-Session-Id` header (MCP 2025-03-26 spec)
- Proper `Receive` replay that handles chunked bodies
- Return JSON-RPC error body (not just HTTP status) on `CoSAIException`
- Tests: test with `httpx.AsyncClient` + ASGI transport

### P3b — wrap_dispatcher
- Add session lifecycle support (wrap `initialize` call to trigger `open_session`)
- Tests: pure unit tests with mock dispatcher

**Panel gate:** T2

---

## Phase 4 — Stub Completions

**Depends on:** P3

**What:** Complete the four remaining engine stubs.

### P4a — T2 AuthzEngine
- Scope claim extraction from validated JWT (`ctx.user_id`, `ctx.tenant_id` set by AuthEngine)
- Per-tool required scope comparison: `required_scopes ⊆ caller_scopes`
- Confused deputy check: if request is server-to-server (no user claim), reject tools marked `user-only`
- Multi-tenant isolation: assert `ctx.tenant_id` matches tenant embedded in tool arguments (configurable per tool)
- **Panel: T1** (new access control logic)

### P4b — T6 IntegrityEngine
- Levenshtein typosquatting check: if `tool_allowlist` provided, any tool within distance ≤ 2 from an allowlist name raises `IntegrityError(severity=HIGH)` if distance ≤ 1, `MEDIUM` if == 2
- Mid-session drift: guard calls `engine.check_drift(ctx, current_tools)` after every `tools/list` re-fetch
- Tool shadowing detection: two tools with names differing only in Unicode lookalikes
- **Panel: T2**

### P4c — T7 SessionEngine
- Server-side session nonce generated at `on_session_start` — never accepted from client
- Transport type recorded at session start; reject requests where transport has changed (cross-transport replay)
- Reject `session_id` appearing in URL query params (leaks via Referer/logs)
- Context bleed: assert session state is cleared on session close — no carry-over
- **Panel: T1** (session security)

### P4d — T11 SupplyChainEngine
- Complete `validate_tools()`: Levenshtein check against allowlist (distance ≤ 2 → warning; exact non-allowlist → `SupplyChainError`)
- Ed25519 registry signature verification (structure: tool JSON + `.json.sig` sidecar, same model as cosai-mcp catalog)
- Dependency confusion: detect tool names matching known public names that shadow internal names
- **Panel: T2**

---

## Phase 5 — FastMCP Adapter

**Depends on:** P3

**What:** Implement `wrap_fastmcp()` once the FastMCP middleware API is stable.

**Scope:**
- Research current FastMCP version's middleware/dispatch hook API
- Implement `wrap_fastmcp(app, guard)` — hook into tool dispatch before and after handler
- Handle `FastMCP` lifespan for `guard.startup()` / `guard.shutdown()`
- Tests: integration test with a real FastMCP server (in-process)

**Panel gate:** T2

---

## Phase 6 — Test Suite

**Depends on:** P1–P5

**What:** Comprehensive test coverage for all 12 engines and the full integration path.

**Structure:**
```
tests/
  engines/
    test_auth.py          T1: missing header, replayed JTI, DPoP failure
    test_authz.py         T2: missing scope, confused deputy, tenant bleed
    test_validation.py    T3: oversized, injection, path traversal, schema
    test_boundary.py      T4: all 18 patterns, definition scan, response scan
    test_protection.py    T5: SSN, CC, email, JWT, API key; each PII profile
    test_integrity.py     T6: drift detection, typosquatting, shadowing
    test_session.py       T7: fixation, cross-transport, URL leak
    test_network.py       T8: 0.0.0.0, SSRF targets, loopback-only
    test_trust.py         T9: length cap, control chars, injection, HTML escape
    test_resources.py     T10: call budget, wall-clock, loop depth
    test_supply_chain.py  T11: allowlist, Levenshtein, registry sig
    test_audit.py         T12: chain integrity, DAG, tamper detection
  adapters/
    test_asgi.py          ArmorMiddleware with httpx.AsyncClient
    test_dispatcher.py    wrap_dispatcher unit tests
  test_guard.py           Full chain integration, ordering, error routing
  test_config.py          cosai.yaml loading, validation, unknown key rejection
  conftest.py             Fixtures: guard instances, mock MCPRequest/Response
```

**Coverage target:** 95% line coverage on all engines. Every CoSAI sub-threat (the 40 vulnerabilities) has at least one test.

**Panel gate:** T3 (test-only)

---

## Phase 7 — CI/CD + PyPI

**Depends on:** P6

**What:** Automated CI, PyPI publishing, version management.

**Scope:**
- `.github/workflows/ci.yml`: lint (ruff), type-check (mypy --strict), test (pytest), coverage gate (95%)
- `.github/workflows/publish.yml`: tag-triggered PyPI publish via trusted publisher (no token stored in secrets)
- `CHANGELOG.md` with conventional commits
- Sigstore attestation on release artifacts (PEP 740)
- `SECURITY.md`: vulnerability disclosure policy

---

## Phase 8 — Examples + Documentation Polish

**Depends on:** P7

**What:** Working examples and complete documentation.

**Scope:**
```
examples/
  fastmcp_basic/     Complete FastMCP server with mcp-armor
  fastapi_basic/     FastAPI + ASGI middleware example
  custom_engine/     How to implement ProtectionEngine for a custom threat
  cosai_yaml_full/   Fully annotated cosai.yaml for a PCI-compliant deployment
```

- `docs/GETTING_STARTED.md`: step-by-step from install to first protected tool call
- `docs/COVERAGE.md`: live coverage matrix (updated from P6 test results)
- `docs/THREAT_MAPPING.md`: CoSAI T1–T12 ↔ ISO 27001 ↔ NIST AI RMF ↔ CWE ↔ OWASP MCP Top 10

---

## Open Issues (pre-Phase 1)

| # | Issue | Blocking | Phase |
|---|-------|----------|-------|
| 1 | `TrustEngine.__init__` typo: `strip_injections` vs `strip_injection_patterns` | No | P1d |
| 2 | `BoundaryEngine._scan()` returns pattern string — callers should get `Finding`, not raw pattern | No | P1a |
| 3 | `AuthzEngine` receives scopes from JWT — needs `AuthEngine` to set `ctx.user_id` first; guard ordering already correct but must be documented | No | P4a |
| 4 | `AuditEngine._write()` uses `self._prev_hash` before the lock in the chain hash calculation — race condition under high concurrency | Yes (P1) | P1 |
| 5 | `wrap_fastmcp` raises `NotImplementedError` — FastMCP middleware API unknown | No | P5 |
| 6 | `cosai.yaml` config loader in `guard.py` uses raw dict access — no schema validation | No | P2 |
