# mcp-armor — Project Context

Read this file at the start of every session before doing any work.

---

## What This Project Is

**mcp-armor** is a server-side protection library for MCP servers. It runs *inside* the target server (not against it) and enforces all 12 CoSAI threat categories (T1–T12) in a single composable middleware chain.

It is the **server-side complement** to the `cosai-mcp` scanner (sibling repo at `~/CoSAI`). The scanner probes from outside; mcp-armor enforces from inside. Together they provide complete coverage.

---

## Sibling Repo

```
~/
  CoSAI/        ← black-box scanner, probe harness, threat catalog
  mcp-armor/    ← this project — server-side SDK
```

The threat taxonomy, CoSAI whitepaper context, and panel decisions all live in `~/CoSAI/docs/`. Read those if you need background on the 12 threat categories.

---

## Key Design Decisions (locked — do not re-litigate)

1. **Option B architecture:** composable primitives + thin framework adapters. The engines are the product; adapters are convenience sugar.

2. **Three-layer model:** threats belong to exactly one layer — Transport/Session (T1,T7,T8,T11), Tool Dispatch (T2,T3,T4,T6,T10), or Response/Re-Feed (T4,T5,T9,T10). Engines run in fixed order; response chain runs reversed.

3. **CoSAIGuard drives everything:** engines never call each other. Guard calls each hook in order.

4. **Fail closed:** all engines raise `CoSAIException` subclasses on violation. No silent return, no logging-only mode.

5. **Immutability throughout:** frozen dataclasses, `tuple`/`MappingProxyType` for containers, `dataclasses.replace()` for mutations, `contextvars.ContextVar` for async-safe per-request state.

6. **RE2 for all regex:** `google-re2` (linear time). Stdlib `re` fallback for dev only with warning.

7. **Escape at ingestion:** `MCPResponse.raw_body` is HTML-escaped at construction time via `html.escape(quote=True)`. Never re-escape downstream.

---

## Current State (as of 2026-04-27)

### What exists
- Full directory structure and `pyproject.toml`
- All 12 engine stubs in `mcp_armor/engines/`
- `CoSAIGuard` with `from_config()`, `default()`, lifecycle hooks
- `CoSAIContext` ContextVar
- Full exception hierarchy (12 typed subclasses + JSON-RPC code map)
- `ArmorMiddleware` (ASGI) — implemented
- `wrap_dispatcher` — implemented
- `wrap_fastmcp` — stub (raises `NotImplementedError`)
- `cosai.yaml.example` — full annotated config
- Full docs suite in `docs/`

### What is implemented (has real logic)
| Engine | Status |
|--------|--------|
| T1 `AuthEngine` | **Complete (P1)** — JWT sig verify, JTI replay (time-based), session binding (sid/session_id), DPoP (RFC 9449): typ, alg, iat asymmetric window, htu/htm binding, jti replay, ath binding, cnf.jkt thumbprint, RSA key size (NIST). Fail-closed. 115 tests pass. |
| T3 `ValidationEngine` | **Complete (P1)** — size limit, cmd/path/SQL injection scan (recursive), JSON schema strict mode, non-dict arg rejection. RE2 with stdlib fallback. |
| T9 `TrustEngine` | **Bug #2 fixed (P1)** — `self._strip_injections` typo resolved. |
| T12 `AuditEngine` | **Bug #1 fixed (P1)** — single-lock atomicity in `_write()`. Full-body chain hash via `_canonical()` covers all auditable fields. |
| T4 `BoundaryEngine` | Partial — 18 patterns, request+response scan done; definition scan at session open missing |
| T5 `ProtectionEngine` | Partial — 5 PII profiles compiled, blocks on match; no redaction |
| T6 `IntegrityEngine` | Partial — manifest hash + drift check done; `check_drift()` not called by guard yet |
| T8 `NetworkEngine` | Partial — `check_bind_address()` + `is_ssrf_target()` done; guard wiring missing |
| T10 `ResourceEngine` | Partial — call count + wall-clock + loop depth done; heartbeat missing |
| T11 `SupplyChainEngine` | Partial — allowlist check done; Levenshtein + sig verification missing |
| T2 `AuthzEngine` | Partial — tool policy lookup + default deny; no scope claim comparison |

### What is stub (no logic)
- `SessionEngine` (T7) — all hooks `return ctx`

---

## Known Bugs (fix before any new feature work)

| # | Severity | Description | File:Line |
|---|----------|-------------|-----------|
| ~~1~~ | ~~High~~ | ~~`AuditEngine._write()` race condition~~ | **Fixed P1** |
| ~~2~~ | ~~Medium~~ | ~~`TrustEngine.__init__` typo~~ | **Fixed P1** |
| 3 | Medium | `IntegrityEngine.check_drift()` exists but is never called by `CoSAIGuard` | `guard.py` |
| 4 | Medium | `NetworkEngine.check_bind_address()` exists but guard never calls it at startup | `guard.py` |
| 5 | Low | `cosai.yaml` loader uses raw dict access — no schema validation on load | `guard.py` |

---

## Relationship to cosai-mcp P10–P13

`cosai-mcp` (the black-box scanner at `~/CoSAI`) and mcp-armor are complementary halves of the same defense posture: the scanner probes from outside and finds what's missing; mcp-armor's engines are the in-process fixes that close those gaps. When cosai-mcp P12 generates a remediation tab for a finding, it points directly to mcp-armor configuration. When an operator installs mcp-armor and configures it correctly, every cosai-mcp P13 adversarial probe against that server should produce PASS (or INCONCLUSIVE), not FINDING. The table below maps each P13 adversarial probe to the specific mcp-armor engine and capability required, along with current implementation status.

**Important:** P13 adversarial probes test the MCP SERVER, not mcp-armor directly. mcp-armor sits inside the server and intercepts the probe payloads before they reach handler logic. A correctly configured mcp-armor installation causes each probe to hit a `CoSAIException` and return a JSON-RPC error — which the probe scores as PASS.

| cosai-mcp probe | Proves | mcp-armor defense | Engine | Status |
|-----------------|--------|-------------------|--------|--------|
| T3-ADV-001 | Injection reaches output path via schema-conformant payload | Recursive RE2 value scan on all string-valued arguments (not just schema conformance check) | `ValidationEngine` | P1c planned — must explicitly be value-level recursive scan |
| T4-ADV-001 | LLM influenced via prompt injection in tool call argument | Prompt injection pattern scan on `tools/call` argument values (not only tool definitions + responses) | `BoundaryEngine` | Missing — new P4e gap |
| T5-ADV-001 | Cross-tenant canary written in session A readable in session B | Tenant context binding: each response tagged to originating session; bleed raises `PIILeakError` | `ProtectionEngine` | T5-003 Not implemented |
| T7-ADV-001 | Session token from session A replayed successfully in session B | Server-generated nonce bound to `Mcp-Session-Id`; replay raises `SessionError` | `SessionEngine` | Complete stub — P4c |
| T11-ADV-001 | Unicode homoglyph tool name (`tooIs_list`) accepted as valid | NFKC normalization before allowlist comparison; homoglyph match raises `SupplyChainError` | `SupplyChainEngine` | Partial (allowlist + Levenshtein planned) — P4d needs homoglyph addition |

### What needs to be built (additions from P13)

- **P4e — BoundaryEngine call-arg prompt injection scan:** `BoundaryEngine.on_request()` currently scans tool definitions (at session open) and responses. It does NOT scan tool call arguments. This is the gap T4-ADV-001 exposes. See workplan.md P4e for full scope.
- **P4c — SessionEngine nonce:** server-generated nonce at `on_session_start` bound to `Mcp-Session-Id`; any request with a non-matching Session-Id raises `SessionError`. Defends T7-ADV-001.
- **P4d — SupplyChainEngine homoglyph detection:** NFKC-normalize all tool names before allowlist comparison. Levenshtein alone misses Unicode lookalikes. Defends T11-ADV-001.
- **P4b — IntegrityEngine homoglyph detection:** normalize tool names to NFKC before comparison; reject any tool name that NFKC-normalizes to a name already in the manifest or allowlist (tool shadowing via Unicode).
- **P10 — cosai-mcp integration layer:** `docs/COSAI_MCP_REMEDIATION.md` mapping every probe ID to a `cosai.yaml` snippet, plus an adversarial test harness in `tests/conftest.py` that exercises the exact payloads P13 sends.

---

## Workplan Summary

See `docs/workplan.md` for the full dependency graph. Short version:

- **P0** ✓ Scaffold complete
- **P1** ✓ **Complete** — Bugs #1/#2 fixed; T1 (JWT+DPoP, 41 tests), T3 (schema+injection, 30 tests), T9 (TrustEngine typo) all done. 115 tests passing.
- **P2** Guard wiring (bugs #3/#4), config schema validation (bug #5)
- **P3** Production-ready adapters (ASGI session lifecycle, dispatcher session lifecycle)
- **P4** Stub completions: T2 scope comparison, T6 Levenshtein, T7 SessionEngine, T11 registry sig
- **P5** FastMCP adapter (pending stable FastMCP middleware API)
- **P6** Full test suite (95% coverage, all 40 sub-threats tested)
- **P7** CI/CD + PyPI
- **P8** Examples + docs polish
- **P9 (future / unscheduled)** TypeScript/Node adapter — needed by VitalSync (`~/vitalsync`) which is a Node.js MCP server. VitalSync is implementing controls natively in TypeScript for now (see `~/vitalsync/MCP_COSAI_T1T12_DESIGN.md`). If a TS adapter ships, VitalSync can adopt it as a drop-in; native controls are compatible with the same spec.
- **P8** Examples + docs polish

---

## Panel Gate Rules (from global CLAUDE.md)

| Work | Tier |
|---|---|
| New auth logic (`AuthEngine`, `AuthzEngine`, `SessionEngine`) | T1 — Full + Adversary (Opus) |
| Non-auth engine work (`BoundaryEngine`, `ValidationEngine`, etc.) | T2 — Sonnet only |
| Test-only changes, typo fixes | T3 — Skip |

---

## File Map

```
mcp_armor/
  __init__.py          Public API
  guard.py             CoSAIGuard — assembly + lifecycle + framework integration
  context.py           CoSAIContext frozen dataclass + ContextVar
  types.py             MCPRequest, MCPResponse, Finding, BudgetState
  exceptions.py        12 typed exceptions + JSON-RPC codes
  engines/
    base.py            ProtectionEngine Protocol
    auth.py            T1
    authz.py           T2
    validation.py      T3
    boundary.py        T4
    protection.py      T5
    integrity.py       T6
    session.py         T7
    network.py         T8
    trust.py           T9
    resources.py       T10
    supply_chain.py    T11
    audit.py           T12
  adapters/
    fastmcp.py         stub
    fastapi.py         ArmorMiddleware (ASGI) — implemented
    dispatcher.py      wrap_dispatcher — implemented
docs/
  DESIGN.md            Original SDK design doc (Option B rationale)
  ARCHITECTURE.md      Three-layer model, engine chain, audit format
  workplan.md          Full phased plan with dependency graph
  COVERAGE.md          All 40 sub-threats: done/partial/stub/not-implemented
  THREAT_MAPPING.md    T1–T12 → OWASP / ISO 27001 / NIST AI RMF / CWE
  GETTING_STARTED.md   Install, config, integration, troubleshooting
  VISION.md            Why, use cases, target users
  SECURITY.md          Disclosure, known limitations
  CONTRIBUTING.md      Standards, panel gates, PR checklist
```
