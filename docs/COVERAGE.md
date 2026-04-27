# mcp-armor — Coverage Status

**Date:** 2026-04-27  
**Status:** Scaffold complete. Core engines partially implemented.

This is the authoritative record of what is implemented, what is stubbed, and what is planned. See [workplan.md](workplan.md) for the roadmap.

---

## Coverage Matrix

| # | Category | Engine | Status | Layer | Notes |
|---|----------|--------|--------|-------|-------|
| T1 | Improper Authentication | `AuthEngine` | **Partial** | Transport | Header presence check done; JWT sig, JTI replay, DPoP → P1b |
| T2 | Missing Access Control | `AuthzEngine` | **Stub** | Dispatch | Tool policy lookup done; scope claim comparison → P4a |
| T3 | Input Validation Failures | `ValidationEngine` | **Stub** | Dispatch | Size limit done; JSON schema + injection → P1c |
| T4 | Data/Control Boundary | `BoundaryEngine` | **Partial** | Dispatch + Response | 18 patterns compiled; definition scan at session open → P1a |
| T5 | Inadequate Data Protection | `ProtectionEngine` | **Partial** | Response | 5 RE2 profiles compiled; blocks on match; no scrub/redact yet |
| T6 | Integrity/Verification | `IntegrityEngine` | **Partial** | Dispatch | Manifest hash + drift check done; Levenshtein → P4b |
| T7 | Session Security Failures | `SessionEngine` | **Stub** | Transport | All hooks return ctx; implementation → P4c |
| T8 | Network Binding Failures | `NetworkEngine` | **Partial** | Startup | `check_bind_address()` + `is_ssrf_target()` done; guard must call these |
| T9 | Trust Boundary Failures | `TrustEngine` | **Partial** | Response | `sanitize()` 5-step pipeline done; fix `strip_injections` typo → P1d |
| T10 | Resource Management | `ResourceEngine` | **Partial** | Dispatch | Call count + wall-clock + loop depth done; heartbeat → P1e |
| T11 | Supply Chain/Lifecycle | `SupplyChainEngine` | **Partial** | Startup | `validate_tools()` allowlist check done; Levenshtein + sig → P4d |
| T12 | Insufficient Logging | `AuditEngine` | **Partial** | All | Hash-chain + DAG done; race condition in `_write()` → P1 fix |

**Legend:** done = implemented and tested · partial = some logic present, gaps identified · stub = file exists, no meaningful logic

---

## What Is Done

### BoundaryEngine (T4) — `engines/boundary.py`
- 18 RE2-compatible injection patterns compiled at construction time
- `on_request()`: scans `tools/call` arguments for injection patterns → raises `InjectionDetectedError`
- `on_response()`: scans `raw_body` for injection patterns → raises `InjectionDetectedError` with `Finding`
- RE2 / stdlib fallback with warning

### ProtectionEngine (T5) — `engines/protection.py`
- Five PII profiles: `minimal`, `pci`, `hipaa`, `gdpr`, `strict`
- Patterns: SSN, credit card, email, phone, JWT, API key
- `on_response()`: blocks if any active pattern matches → raises `PIILeakError`
- Gap: blocks but does not redact — response is aborted rather than scrubbed

### IntegrityEngine (T6) — `engines/integrity.py`
- `_manifest_hash()`: SHA-256 of canonicalised tools list (sorted by name, sort_keys=True)
- `check_drift()`: compares current hash against `ctx.tool_manifest_hash` — raises `IntegrityError` if mismatch
- `_levenshtein()`: pure-Python edit distance (no dependency) — used for typosquatting check (threshold configurable)
- Gap: guard does not yet call `check_drift()` — wiring needed in P2

### ResourceEngine (T10) — `engines/resources.py`
- `on_request()`: checks `calls_used`, `elapsed`, `loop_depth` before dispatch → raises `ResourceExceededError`
- `budget.increment()` called per tool dispatch
- Gap: `budget.descend()` not yet called for nested tool calls (guard wiring → P2)

### AuditEngine (T12) — `engines/audit.py`
- Hash-chained JSON Lines: `chain_hash = SHA-256(prev_hash + entry_id)`
- DAG: `parent_id` set via `ctx.audit_parent_id` — enables tree reconstruction
- `verify_chain()`: walks file, raises `AuditChainError` at first broken link
- Params stored as SHA-256 digest — no PII in logs
- **Known issue:** `self._prev_hash` read/written outside the lock in `_write()` — race condition under concurrent requests. Fix in P1.

### NetworkEngine (T8) — `engines/network.py`
- `check_bind_address()`: raises `NetworkBindingError` for `0.0.0.0` / `::` unless `allow_public_bind=True`
- `is_ssrf_target()`: resolves hostname and checks against RFC1918 / loopback / link-local / IPv6 ULA
- Gap: guard does not call these at startup — wiring in P2

### SupplyChainEngine (T11) — `engines/supply_chain.py`
- `validate_tools()`: rejects tools not in allowlist → raises `SupplyChainError`
- Gap: allowlist = `[]` (empty list) currently means deny-all; `None` means allow-all. Document this explicitly.

### AuthEngine (T1) — `engines/auth.py`
- `on_request()`: checks `Authorization: Bearer ...` header presence
- Gap: no JWT parsing, no JTI cache, no DPoP — all → P1b

### AuthzEngine (T2) — `engines/authz.py`
- `on_request()`: looks up tool name in `tool_policies` dict
- Default deny: tools with no policy entry raise `AuthorizationError`
- Gap: no scope claim extraction — requires AuthEngine to set `ctx.user_id` first

---

## What Is Stubbed (no logic)

| Engine | File | Planned Phase |
|--------|------|---------------|
| SessionEngine | `engines/session.py` | P4c |
| ValidationEngine (full) | `engines/validation.py` | P1c |
| TrustEngine (bug fix) | `engines/trust.py` | P1d |

---

## Known Issues

| # | Severity | Description | File | Phase |
|---|----------|-------------|------|-------|
| 1 | **High** | `AuditEngine._write()` race condition: `self._prev_hash` read outside lock | `engines/audit.py` | P1 |
| 2 | Medium | `TrustEngine.__init__` uses `strip_injections` but param is `strip_injection_patterns` | `engines/trust.py` | P1d |
| 3 | Medium | `IntegrityEngine.check_drift()` never called — guard wiring missing | `guard.py` | P2 |
| 4 | Medium | `NetworkEngine.check_bind_address()` never called — guard wiring missing | `guard.py` | P2 |
| 5 | Low | `ProtectionEngine` blocks on PII match but does not redact — response is aborted | `engines/protection.py` | P4 |
| 6 | Low | `cosai.yaml` loader uses raw dict access — no schema validation | `guard.py` | P2 |
| 7 | Low | `wrap_fastmcp` raises `NotImplementedError` | `adapters/fastmcp.py` | P5 |

---

## Sub-Threat Coverage (40 vulnerabilities)

| Sub-threat | Code | Status |
|------------|------|--------|
| Missing auth header | T1-001 | Partial (header presence only) |
| Token replay (JTI) | T1-002 | Not implemented |
| Cross-session token reuse | T1-003 | Not implemented |
| DPoP binding failure | T1-004 | Not implemented |
| Confused deputy | T2-001 | Stub (tool lookup done, no scope comparison) |
| Missing per-tool RBAC | T2-002 | Stub |
| Multi-tenant data bleed | T2-003 | Stub |
| Oversized payload | T3-001 | Partial (byte count check) |
| Command injection | T3-002 | Stub (no RE2 scan yet) |
| Path traversal | T3-003 | Stub |
| SQL injection | T3-004 | Stub |
| Injection in tool definition | T4-001 | Done (18 patterns) |
| Injection in tool response | T4-002 | Done |
| SSN / CC / PII in response | T5-001 | Done (blocks; no redact) |
| JWT / API key in response | T5-002 | Done |
| Foreign session context bleed | T5-003 | Not implemented |
| Mid-session tool mutation | T6-001 | Done (hash drift detection) |
| Tool typosquatting | T6-002 | Partial (Levenshtein impl; no probe call) |
| Tool shadowing | T6-003 | Not implemented |
| Session fixation | T7-001 | Stub |
| Token in URL | T7-002 | Stub |
| Cross-transport replay | T7-003 | Stub |
| Context bleed between sessions | T7-004 | Stub |
| Server bound to 0.0.0.0 | T8-001 | Done (startup check; guard wiring missing) |
| SSRF via tool args | T8-002 | Done (SSRF target detection; guard wiring missing) |
| Shadow MCP server detection | T8-003 | Not implemented |
| Unsanitized LLM output re-feed | T9-001 | Done (5-step pipeline, bug in init) |
| LLM-generated commands executed | T9-002 | Partial |
| LLM as security gate | T9-003 | Not implemented |
| Unbounded call count | T10-001 | Done |
| Wall-clock limit exceeded | T10-002 | Done |
| Recursive tool call loop | T10-003 | Done |
| Missing heartbeat | T10-004 | Not implemented |
| Unlisted tool loaded | T11-001 | Done |
| Typosquatted package | T11-002 | Not implemented |
| Unsigned tool from registry | T11-003 | Not implemented |
| Dependency confusion | T11-004 | Not implemented |
| No execution trace | T12-001 | Done |
| Log tampering | T12-002 | Done (chain verify) |
| PII in logs | T12-003 | Done (digest only) |
| Missing DAG parent | T12-004 | Done |
