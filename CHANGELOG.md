# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Versioning & provenance note (A5)

Earlier releases left the version line incoherent: `pyproject.toml` read `0.1.0`,
the last commit message claimed `v0.2.0`, **PyPI served `1.0.0`–`1.0.2`**, and the
repo had **no git tags** — so an installed artifact could not be traced to a
commit. This is reconciled going forward:

- `pyproject.toml` is now `1.1.0` — the next release **above** the highest
  published artifact (`1.0.2`), so version order is monotonic and unambiguous.
- Every release from here is mapped to its commit in this file and **must be git
  tagged** `vX.Y.Z` so `publish.yml` (PyPI OIDC trusted publishing + Sigstore
  provenance) ships a traceable artifact.

**Operator action required (tagging/publish is operator-owned):**
```bash
git tag -a v1.1.0 -m "v1.1.0 — audit remediation"   # on the commit that lands this release
git push origin v1.1.0                               # triggers publish.yml
```
Until `v1.1.0` is tagged and published, PyPI's latest remains `1.0.2`.

## [Unreleased]

### Security — hardened

- **RFC 9449 §4.3 enforcement (T1): DPoP-bound tokens must carry `cnf.jkt`.**
  When DPoP is in force (`require_dpop=True` or a DPoP proof is presented),
  the access token MUST be sender-constrained via a `cnf.jkt` claim. Without
  this check, a stolen non-bound token could be replayed with any attacker-minted
  valid DPoP proof, defeating the binding guarantee. `AuthEngine.on_request` now
  fails closed: when DPoP is in force and `cnf.jkt` is absent, raises
  `AuthenticationError(RFC 9449 §4.3)`. Gated behind new `require_cnf_binding`
  flag (default `True`) for operators using non-conformant issuers. See config
  `T1.require_cnf_binding` and `docs/THREAT_MAPPING.md` (T1 sub-threat T1-004b).

### Added

- **T1 config: `require_cnf_binding`** — flag to enforce DPoP sender-constraint
  (RFC 9449 §4.3). Defaults `True` (fail-closed). Set `False` only when using
  issuers that do not mint DPoP-bound tokens.

### Tests

- 4 new regression tests entering at `AuthEngine.on_request`:
  `test_regression_dpop_without_cnf_jkt_rejected` (require_dpop path),
  `test_regression_dpop_proof_without_cnf_jkt_rejected_even_if_not_required`
  (proof-present path), `test_dpop_without_cnf_jkt_accepted_when_binding_opt_out`
  (opt-out path), `test_regression_bearer_no_dpop_cnf_gate_not_triggered`
  (non-DPoP path completeness).
- 12 existing DPoP property-isolation tests downgraded to `require_cnf_binding=False`
  to isolate the gate from the property each test targets.

**Test count:** 587 passing (586 → +1 completeness test).

## [1.1.0] — 2026-06-12

Audit remediation release — closes every finding (A1–C3) in
`docs/AUDIT_2026-06-12.md` (three-lens: live attack rig + enterprise-fit review +
defense-honesty trace). 577 tests passing (up from 563). Maps to commit: _this
release_ (tag `v1.1.0`).

### Security — fixed

- **A1 (T3, CRITICAL): JSON-schema validation was dead on every live path.**
  `ValidationEngine._tool_schemas` was never populated by any adapter, so with the
  default `strict_schema=True` **every** `tools/call` was rejected with "no
  registered schema" (self-DoS). `ValidationEngine.on_response` now auto-registers
  each tool's `inputSchema` from the observed `tools/list` response (mirroring
  `IntegrityEngine`/`SupplyChainEngine`). A schema-valid call passes; an
  `inputSchema` violation is blocked with `-32602`.
- **A4 (T12): audit rollback-to-empty bypass closed.** Deleting the log made
  `path.exists()` False so startup re-seeded an empty chain with no verification.
  Startup now raises `AuditChainError` when the log is absent but its `.hwm`
  sidecar or `.hmac_enabled` marker survives.
- **A6 (T12/T11): defaults now match docs.** `ARMOR_AUDIT_HMAC_KEY` is **required**
  at startup when T12 is enabled (`T12.require_hmac_key` defaults `true`; dev
  opt-out via `require_hmac_key: false` or `ARMOR_AUDIT_ALLOW_UNSIGNED=1`). README
  no longer claims Ed25519 registry signatures are enforced "by default" — they
  remain **opt-in** (`require_registry_signature`).
- **C2 (T1): `_check_rsa_key_size` now fails closed.** A DPoP RSA key with an
  undecodable modulus is rejected instead of silently skipping the NIST key-size
  floor.

### Changed

- **A2 (T7): the no-op DPoP-binding label was removed.** `SessionEngine` no longer
  takes `bind_to_dpop` and the `T7.bind_session_to_dpop` YAML key is removed
  (now rejected as unknown). T7 is documented as **transport-bound session
  continuity**; DPoP sender-constraint is enforced by T1 via the access token's
  `cnf.jkt` claim. **Breaking:** configs setting `bind_session_to_dpop` must drop
  the key.
- **A3 (T8): the startup `0.0.0.0` bind check is now wired from config.** `T8`
  gains `bind_host`/`bind_port`; when `bind_host` is set, `guard.startup()` raises
  `NetworkBindingError` on a public bind unless `allow_public_bind: true`.
- **B6: `dry_run` has a hard prod guard.** `CoSAIGuard(dry_run=True)` now refuses
  to construct unless `ARMOR_ALLOW_DRY_RUN=1` is set, and logs at ERROR.
- **B1: response engines documented as BLOCK, not scrub.** `ProtectionEngine`
  (T5) and `TrustEngine` (T9) `on_response` raise (whole response replaced with an
  opaque error); they do not redact in place. Docstrings corrected; `TrustEngine.
  sanitize()` remains the explicit-call redaction helper.
- **C1: dependencies gained upper bounds** (`<next-major`) so a breaking release of
  a security-relevant dep cannot be silently pulled in; lockfile guidance added.

### Added

- **B2: a runnable quickstart** — `examples/quickstart/cosai.yaml` boots on
  localhost with a single env var. `cosai.yaml.example` now documents every
  required env var / prerequisite in a header and builds with a sample JWKS.
- **B5: a benchmark harness** — `benchmarks/chain_overhead.py` reports p50/p99 of
  the engine chain (published in README/ARCHITECTURE) with a CI smoke test.
- Named regression tests for every finding, entering at the public entry point
  (adapter → guard → engine): `tests/test_remediation_audit_2026_06_12.py`,
  `test_regression_a1_*` (adapter), `test_regression_c2_*` (auth).

### Documented (honesty, no behavior change)

- **B3:** the dispatcher adapter mints a fresh session per call → no cross-call
  T6/T10 accumulation (single-call-session only).
- **B4:** the T6 manifest baseline is in-process; multi-worker is fail-open until a
  shared session store exists — run a single worker for T6/T7/T10 continuity.
- **B7:** the destructive-tool confirm-token gate provides no protection for fully
  autonomous agents (pair with RFC 9470 step-up).
- **B8:** `docs/TYPESCRIPT.md` is labelled a DIY recipe — no sidecar module/image
  ships today.
- **C3:** SIEM/compliance export is file-tail-only today (no SIEM/SOAR emitter).

## [0.2.0] — 2026-05-28

Security hardening release closing 19 findings across AuditEngine, BoundaryEngine,
ResourceEngine, guard, and config. 563 tests passing (up from 508).

### Security

- **AuditEngine: concurrent write race fixed** — `asyncio.Lock` wraps seq assignment
  and the `asyncio.to_thread` disk write in a single atomic unit; no two coroutines
  can produce entries with the same `prev_hash`.
- **`dry_run` never suppresses auth errors** — `AuthorizationError` and
  `AuthenticationError` always re-raise in both request and response chains even when
  `dry_run=True`. Only non-auth violations are logged-and-continued.
- **`@guard.protect(threats=[...])` forces auth engines** — `AuthEngine` (T1) and
  `AuthzEngine` (T2) are force-included in the active engine list regardless of the
  `threats=` filter, preventing inadvertent auth bypass via `threats=["T3"]`.
- **BoundaryEngine Base64 loop capped at 8 tokens** — CPU DoS via crafted truncated
  input prevented; `_BASE64_MAX_MATCHES = 8` and `_BASE64_MAX_DECODED_CHARS = 512`
  budget the decode surface per call.
- **`asyncio.get_event_loop()` replaced with `get_running_loop()`** — avoids the
  deprecated 3.10+ API and the wrong-loop bug in coroutine context.
- **HMAC key validated at startup** — `ARMOR_AUDIT_HMAC_KEY` is parsed to bytes at
  `AuditEngine.__init__` (stored as `self._hmac_key`); invalid hex raises `ConfigError`
  immediately rather than failing on every write.
- **`ARMOR_AUDIT_HMAC_KEY_PREV` for zero-downtime key rotation** — old records signed
  with the previous key are accepted with a WARNING log entry during the rotation
  grace period; neither key version is silently lost.
- **ContextVar reset via token in `finally`** — `_active_ctx` is always reset at the
  end of an ASGI request regardless of exceptions, preventing context bleed between
  requests on the same async task.
- **Reaper eviction callback wired to `ArmorMiddleware._active_sessions`** — zombie
  sessions evicted by `ResourceEngine._reaper_loop` are now also removed from the
  middleware's own session store via the `eviction_callback` hook.
- **`_GuardedToolDispatcher` sets `_active_ctx`** — FastMCP-wrapped tools now see the
  live `CoSAIContext` (with real JWT scopes) via `_active_ctx` exactly as ASGI tools do.
- **`.hmac_enabled` sticky marker prevents silent HMAC downgrade** — once a log has
  been written with HMAC enabled, startup raises `AuditChainError` if `ARMOR_AUDIT_HMAC_KEY`
  is absent, preventing an attacker from disabling HMAC by unsetting the env var.

### Internal / Correctness

- **AuditEngine file I/O moved off event loop** — all disk operations (`_sync_append_record`,
  `_sync_write_hwm`) dispatched via `asyncio.to_thread`; the event loop is never blocked
  by audit log writes.
- **`@guard.protect` uses live ASGI `ContextVar`** — decorators executing inside an
  active HTTP request read the context from `_active_ctx` ContextVar rather than
  constructing a blank stdio context, ensuring per-tool policy sees real JWT scopes.
- **ResourceEngine heartbeat reaper now starts** — `on_startup()` creates the background
  reaper task via `asyncio.get_running_loop().create_task()`; previously the task was
  silently never started.
- **HMAC audit chain signing** — optional `ARMOR_AUDIT_HMAC_KEY` adds an unforgeable
  `chain_hmac` field (HMAC-SHA256) to every audit record, closing the log-truncation-
  and-recalculation gap present in pure SHA-256 chaining.
- **`echo_confirm_token` paradox documented** — the inescapable tradeoff is documented
  in `SECURITY.md`: `false` (default) breaks fully automated clients; `true` allows
  autonomous agents to auto-resubmit. The gate is only meaningful when a human
  intercepts the error before it reaches the agent.
- **`dry_run` mode added** — `CoSAIGuard(dry_run=True)` and `dry_run: true` in
  `cosai.yaml` log violations at WARNING and audit them as `"dry_run_violation"` events
  without blocking requests. `NOT FOR PRODUCTION`.
- **BoundaryEngine normalization pipeline** — `_normalize_for_injection_scan()` adds
  whitespace collapse, zero-width / soft-hyphen stripping, bidi override char stripping,
  and Base64 decode-and-rescan before pattern matching, closing obfuscation bypasses.
- **`load_config` warns when `dry_run: true` loaded from YAML** — emits a WARNING log
  immediately on parse so the setting is never silently active in production.

**Test count:** 563 passing (was 508; +55 new tests covering the above)

## [Unreleased]

### Added
- **Input validation hardening** (three gaps closed):
  - **T4-003 — Tool manifest description scanning:** `BoundaryEngine.on_response` now scans
    every tool `description` field from `tools/list` responses against the full 24-pattern
    injection library. A poisoned tool description raises `InjectionDetectedError(T4-003)`
    before the manifest is accepted. Gated by the existing `scan_responses` flag.
  - **ReDoS length cap:** `BoundaryEngine._scan()` truncates strings to `_MAX_SCAN_LEN`
    (8,192 chars) before regex scanning to bound worst-case time when `google-re2` is absent.
  - **Compression bomb defence:** `ArmorMiddleware` rejects any `Content-Encoding` other than
    `identity` with `-32600` before buffering begins. The pre-parse byte cap previously only
    covered raw bytes; a gzip bomb could produce an unbounded decompressed payload.
- **P2 — Typed config system**: `ArmorConfig` frozen dataclasses, `load_config()` with
  unknown-key rejection; `CoSAIContext.scopes` and `.transport` fields; guard factory wired
  to `ArmorConfig`
- **P4a — AuthzEngine** (T2): RBAC required-scopes, confused-deputy (`user_only`), tenant
  isolation default-deny, destructive two-stage commit gate with `_TokenStore`
  (constant-time compare, tool-keyed tokens, lazy eviction)
- **P4b — IntegrityEngine** (T6): NFKC-normalized Levenshtein typosquat detection, homoglyph
  shadowing check, manifest-drift guard; duplicate tool name detection (panel FIX-1)
- **P4c — SessionEngine** (T7): Session fixation prevention, cross-transport replay detection,
  URL session_id leak guard (T7-002), context-bleed cleanup on session end; `initialize`
  always verified against store (panel FIX-4/5)
- **P4d — SupplyChainEngine** (T11): NFKC Levenshtein allowlist, Ed25519 registry signature
  verification with proper exception narrowing (panel FIX-3/4)
- **P4e — BoundaryEngine** (T4): Recursive `_scan_values`, 6 OWASP LLM Top-10 A01-A06
  call-arg patterns, tool name scanning (panel FIX-5)
- **P3 — ArmorMiddleware** (ASGI): Correct `Mcp-Session-Id` header, server-generated session
  IDs, `open_session`/`close_session` lifecycle, opaque JSON-RPC error responses, percent-
  decoded query-string T7-002 detection, `Content-Type` enforcement, body-size cap during
  buffering, WebSocket scope guard (7 panel findings resolved)
- **P5 — FastMCP adapter**: `wrap_fastmcp()` with `isinstance` guard, `_GuardedToolDispatcher`
  with session leak fix (`finally` drain), configurable transport, `html.escape` on response
  body (4 panel findings resolved)
- **P6 — Full test suite**: 329 tests, 90% coverage; engines for T5/T8/T9/T10 fully covered;
  guard factory, lifecycle, and adapter composition tests added
- **P7 — CI/CD**: GitHub Actions `ci.yml` (matrix 3.11/3.12, ruff, mypy, coverage gate 88%);
  `publish.yml` with PyPI trusted publisher (OIDC), Sigstore attestation, pre-publish smoke test

### Fixed
- Session fixation via `payload["id"]` in dispatcher adapter (Opus panel finding)
- `_TokenStore` self-referential `compare_digest` timing oracle (P0 panel FIX-2)
- Token cross-tool replay: tokens now keyed by `(session_id, tool_name)` (panel FIX-6)
- Tenant isolation silent bypass when `tenant_id` absent from arguments (panel FIX-3/7)
- `IntegrityEngine` duplicate ASCII tool names not caught (panel FIX-1)
- `SupplyChainEngine.on_startup()` raising `ValueError` instead of `SupplyChainError` (panel FIX-3)
- `except Exception` in `_verify_signature` replaced with specific `(InvalidSignature, binascii.Error)` (panel FIX-4)
- `ArmorMiddleware` wrong session header (`x-mcp-session-id` → `Mcp-Session-Id`)

## [0.1.0] — 2026-04-01

### Added
- Initial scaffold: 12-engine guard chain (T1–T12 stubs), `CoSAIGuard`, `CoSAIContext`,
  `MCPRequest`/`MCPResponse` frozen types, exception hierarchy, ASGI/dispatcher/FastMCP
  adapter stubs
