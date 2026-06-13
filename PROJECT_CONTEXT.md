# mcp-armor — Project Context

Read this file at the start of every session before doing any work.

---

## What This Project Is

**mcp-armor** is a server-side protection library for MCP servers. It runs *inside* the
target server and enforces all 12 CoSAI threat categories (T1–T12) in a single composable
middleware chain.

It is the **server-side complement** to the `cosai-mcp` scanner. The scanner probes from
outside; mcp-armor enforces from inside. Together they provide complete coverage.

**Current production user:** VitalSync (TypeScript MCP server) uses mcp-armor via the HTTP
sidecar proxy pattern. See [docs/TYPESCRIPT.md](docs/TYPESCRIPT.md).

---

## Key Design Decisions (locked — do not re-litigate)

1. **Option B architecture:** composable primitives + thin framework adapters. The engines
   are the product; adapters are convenience sugar.

2. **Three-layer model:** Transport/Session (T1, T7, T8, T11) → Tool Dispatch (T2, T3, T4,
   T6, T10) → Response/Re-Feed (T4, T5, T9, T10). Engines run in fixed order; response
   chain runs reversed.

3. **CoSAIGuard drives everything:** engines never call each other.

4. **Fail closed:** all engines raise `CoSAIException` subclasses on violation.

5. **Immutability throughout:** frozen dataclasses, `tuple`/`MappingProxyType` for
   containers, `dataclasses.replace()` for mutations, `contextvars.ContextVar` for
   async-safe per-request state.

6. **RE2 for all regex:** `google-re2` (linear time). Stdlib `re` fallback for dev only
   with a warning log.

7. **Escape at ingestion:** `MCPResponse.raw_body` is HTML-escaped at construction time
   via `html.escape(quote=True)`. Never re-escape downstream.

---

## Current State (v1.1.0 — 2026-06-12)

**All 12 engines are fully implemented and tested. No stubs remain.**

Version is reconciled to **1.1.0** after the external security audit remediation (previously
inconsistent: pyproject 0.1.0, PyPI 1.0.2, no git tags). Operator must `git tag v1.1.0` to
match the source of truth.

| Component | Status |
|-----------|--------|
| All 12 engines (T1–T12) | ✅ Implemented |
| `ArmorMiddleware` (ASGI) | ✅ Implemented |
| `wrap_fastmcp` | ✅ Implemented |
| `wrap_dispatcher` | ✅ Implemented |
| `guard.protect()` per-tool decorator | ✅ Implemented |
| Typed `ArmorConfig` / `cosai.yaml` loader | ✅ Implemented |
| CI — GitHub Actions matrix (3.11/3.12) | ✅ Live |
| PyPI trusted publisher workflow | ✅ Ready |
| Test suite | ✅ 577 tests, 90%+ coverage |
| Examples | ✅ quickstart (boots with `ARMOR_SESSION_SECRET` only), fastmcp_basic, fastapi_basic, custom_engine, cosai_yaml_full |
| Docs | ✅ All current |

**Enforced behavior (v1.1.0 — locked):**
- Response engines (T4/T5/T9) **block** — a violation raises and an opaque error replaces the
  whole response; they do not scrub/strip/redact in place. Only `TrustEngine.sanitize()`
  (an explicit call) redacts.
- T3 JSON-schema validation is **live**: a tool's `inputSchema` auto-registers from the
  observed `tools/list` response; a schema-valid `tools/call` passes, a violation → `-32602`.
- T7 is transport-bound session **continuity** only. The `bind_session_to_dpop` flag was
  removed; DPoP sender-constraint is enforced by T1 via the access-token `cnf.jkt` claim.
- T11 blocks typosquats / non-allowlisted tools by default; Ed25519 registry signature
  verification is opt-in (`require_registry_signature`, default false).
- T12 HMAC signing is required by default (`T12.require_hmac_key` true; `ARMOR_AUDIT_HMAC_KEY`
  must be set at startup). Dev opt-out: `require_hmac_key: false` or `ARMOR_AUDIT_ALLOW_UNSIGNED=1`.
- `dry_run` refuses to construct unless `ARMOR_ALLOW_DRY_RUN=1` is set.
- SIEM/SOAR export is file-tail-only today — T12 writes portable JSONL a SIEM can tail;
  no emitter ships yet.
- Benchmarks: `benchmarks/chain_overhead.py` (Apple M5, 20k iters) — CPU scan chain
  p50 ≈ 115 µs / p99 ≈ 158 µs; full chain incl T12 audit disk I/O p50 ≈ 608 µs / p99 ≈ 810 µs.

**Known limitations (not bugs):**
- T10 heartbeat config accepted but background monitor not implemented
- TypeScript servers require the sidecar proxy pattern (see [docs/TYPESCRIPT.md](docs/TYPESCRIPT.md))

---

## File Map

```
mcp_armor/
  __init__.py          Public API: CoSAIGuard, CoSAIContext, all exceptions
  guard.py             CoSAIGuard — assembly, lifecycle, framework integration
  config.py            Typed ArmorConfig frozen dataclasses + cosai.yaml loader
  context.py           CoSAIContext frozen dataclass + ContextVar
  types.py             MCPRequest, MCPResponse, Finding, BudgetState
  exceptions.py        12 typed exceptions + JSON-RPC codes
  engines/
    base.py            ProtectionEngine Protocol
    auth.py            T1 — JWT, DPoP, JTI replay
    authz.py           T2 — RBAC, confused deputy, destructive gate
    validation.py      T3 — size limit, injection scan, schema strict mode
    boundary.py        T4 — OWASP prompt injection patterns, recursive scan
    protection.py      T5 — PII scrubbing (5 profiles)
    integrity.py       T6 — NFKC homoglyph, Levenshtein, drift detection
    session.py         T7 — fixation prevention, transport binding
    network.py         T8 — bind address, SSRF detection
    trust.py           T9 — LLM output sanitization (5-step pipeline)
    resources.py       T10 — call budget, wall-clock, loop depth
    supply_chain.py    T11 — allowlist, Ed25519 sig, NFKC homoglyph
    audit.py           T12 — hash-chained JSON Lines log
  adapters/
    fastmcp.py         wrap_fastmcp — FastMCP integration
    fastapi.py         ArmorMiddleware — ASGI middleware
    dispatcher.py      wrap_dispatcher — raw JSON-RPC callable

docs/
  GETTING_STARTED.md   Step-by-step install, config, integration, troubleshooting
  TYPESCRIPT.md        How to use with TypeScript / non-Python servers (sidecar proxy)
  COVERAGE.md          Full sub-threat coverage matrix with test references
  COSAI_MCP_REMEDIATION.md  T1–T12 threat → engine → test mapping
  ARCHITECTURE.md      Three-layer model, engine chain, module map
  DESIGN.md            SDK design rationale (Option B)
  THREAT_MAPPING.md    T1–T12 → OWASP / ISO 27001 / NIST AI RMF / CWE
  VISION.md            Why, use cases, target users
  SECURITY.md          Disclosure policy, design principles, known limitations
  CONTRIBUTING.md      Standards, panel gates, PR checklist

examples/
  quickstart/          Runnable cosai.yaml — boots with just ARMOR_SESSION_SECRET
  fastmcp_basic/       FastMCP server wrapped with mcp-armor
  fastapi_basic/       FastAPI + ArmorMiddleware
  custom_engine/       How to write a ProtectionEngine subclass
  cosai_yaml_full/     Fully annotated cosai.yaml for all 12 threats
```

---

## Panel Gate Rules (from global CLAUDE.md)

| Work | Tier |
|---|---|
| Auth logic — `AuthEngine`, `AuthzEngine`, `SessionEngine`, new auth handshake | T1 — Full + Adversary (Opus) |
| Non-auth engine work, adapters, config | T2 — Sonnet only |
| Test-only changes, typo fixes, comments | T4 — Skip |
