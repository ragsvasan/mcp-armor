# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
