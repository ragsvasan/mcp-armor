# mcp-armor — Coverage Status

**Version:** 1.1.0  
**Date:** 2026-06-12  
**Tests:** 563 passing · Coverage: 90%+

All 12 CoSAI threat engines are fully implemented and tested. No stubs remain.

A dedicated adversarial integration suite (`tests/adversarial/`) exercises the full
public deployment path — `ArmorMiddleware` and `wrap_dispatcher` — not engine unit
internals alone. Every documented threat claim has at least one end-to-end test that
asserts the client receives only an opaque error, never the sensitive or injected body.

---

## Coverage Matrix

| # | Category | Engine | Status | Layer | Tests |
|---|----------|--------|--------|-------|-------|
| T1 | Improper Authentication | `AuthEngine` | **Done** | Transport | `tests/engines/test_auth.py` |
| T2 | Missing Access Control | `AuthzEngine` | **Done** | Dispatch | `tests/engines/test_authz.py` |
| T3 | Input Validation Failures | `ValidationEngine` | **Done** | Dispatch | `tests/engines/test_validation.py` |
| T4 | Data/Control Boundary | `BoundaryEngine` | **Done** | Dispatch + Response | `tests/engines/test_boundary.py` |
| T5 | Inadequate Data Protection | `ProtectionEngine` | **Done** | Response | `tests/engines/test_protection.py` |
| T6 | Integrity/Verification | `IntegrityEngine` | **Done** | Dispatch | `tests/engines/test_integrity.py` |
| T7 | Session Security Failures | `SessionEngine` | **Done** | Transport | `tests/engines/test_session.py` |
| T8 | Network Binding Failures | `NetworkEngine` | **Done** | Startup | `tests/engines/test_network.py` |
| T9 | Trust Boundary Failures | `TrustEngine` | **Done** | Response | `tests/engines/test_trust.py` |
| T10 | Resource Management | `ResourceEngine` | **Done** | Dispatch + Response | `tests/engines/test_resources.py` |
| T11 | Supply Chain/Lifecycle | `SupplyChainEngine` | **Done** | Startup | `tests/engines/test_supply_chain.py` |
| T12 | Insufficient Logging | `AuditEngine` | **Done** | All (wraps chain) | `tests/engines/test_audit.py` |

---

## Sub-Threat Coverage

| Sub-threat | Code | Status | Engine | Test |
|------------|------|--------|--------|------|
| Missing/invalid auth header | T1-001 | ✅ Done | `AuthEngine` | `test_missing_token_rejected` |
| `alg: none` JWT downgrade | T1-002 | ✅ Done | `AuthEngine` | `test_none_algorithm_rejected` |
| Token replay (JTI) | T1-003 | ✅ Done | `AuthEngine` | `test_jti_replay_rejected` |
| DPoP binding failure | T1-004 | ✅ Done | `AuthEngine` | `test_dpop_wrong_key_rejected` |
| Weak RSA key (< 2048 bit) | T1-005 | ✅ Done | `AuthEngine` | `test_dpop_weak_rsa_key_rejected` |
| Tool call without required scope | T2-001 | ✅ Done | `AuthzEngine` | `test_missing_required_scope_denied` |
| Confused deputy (server-to-server) | T2-002 | ✅ Done | `AuthzEngine` | `test_user_only_tool_without_user_denied` |
| Cross-tenant argument forgery | T2-003 | ✅ Done | `AuthzEngine` | `test_tenant_isolated_mismatched_tenant_denied` |
| Destructive tool without confirm token | T2-004 | ✅ Done | `AuthzEngine` | `test_destructive_tool_no_token_denied` |
| Confirm token reuse (single-use) | T2-005 | ✅ Done | `AuthzEngine` | `test_destructive_token_single_use` |
| Token cross-tool replay | T2-006 | ✅ Done | `AuthzEngine` | `test_regression_confirm_token_not_transferable_across_tools` |
| tools/list scope filter (T02-004/D-05) | T2-007 | ✅ Done | `AuthzEngine` + `ArmorMiddleware` | `test_filter_tools_list_hides_tool_requiring_missing_scope`, `test_tools_list_scope_filter_hides_unpermitted_tools` |
| Oversized payload | T3-001 | ✅ Done | `ValidationEngine` | `test_oversized_payload_rejected` |
| Shell metacharacters in arguments | T3-002 | ✅ Done | `ValidationEngine` | `test_shell_injection_in_args_rejected` |
| Path traversal | T3-003 | ✅ Done | `ValidationEngine` | `test_path_traversal_in_args_rejected` |
| SQL injection | T3-004 | ✅ Done | `ValidationEngine` | `test_sql_injection_in_args_rejected` |
| JSON-Schema violation (auto-registered from `tools/list`) | T3-006 | ✅ Done | `ValidationEngine` + adapter | `test_regression_a1_input_schema_violation_blocked`, `test_regression_a1_valid_tools_call_passes_after_tools_list` |
| Injection in tool definitions | T4-001 | ✅ Done | `BoundaryEngine` | `test_owasp_a01_ignore_previous_instructions` |
| Role-override preamble | T4-002 | ✅ Done | `BoundaryEngine` | `test_owasp_a04_you_are_now` |
| System prompt reveal | T4-003 | ✅ Done | `BoundaryEngine` | `test_owasp_a06_system_prompt` |
| Injection in tool call arguments | T4-004 | ✅ Done | `BoundaryEngine` | `test_regression_injection_in_tool_name_param_detected` |
| Injection in tool response body | T4-005 | ✅ Done | `BoundaryEngine` | `test_injection_in_response_raises` |
| Nested dict injection (indirect) | T4-006 | ✅ Done | `BoundaryEngine` | `test_nested_dict_injection_detected` |
| Injection in tool manifest description | T4-007 | ✅ Done | `BoundaryEngine` | `test_regression_injection_in_tool_description_detected` |
| Compressed body (gzip/deflate) | T3-005 | ✅ Done | `ArmorMiddleware` | `test_regression_gzip_content_encoding_rejected` |
| SSN in response | T5-001 | ✅ Done | `ProtectionEngine` | `test_ssn_in_response_blocked_pci` |
| Credit card in response | T5-002 | ✅ Done | `ProtectionEngine` | `test_credit_card_in_response_blocked_pci` |
| JWT token in response | T5-003 | ✅ Done | `ProtectionEngine` | `test_jwt_in_response_blocked_pci` |
| API key in response | T5-004 | ✅ Done | `ProtectionEngine` | `test_api_key_in_response_blocked_pci` |
| Email in response (GDPR) | T5-005 | ✅ Done | `ProtectionEngine` | `test_email_in_response_blocked_strict` |
| Typosquatted tool name (d=1) | T6-001 | ✅ Done | `IntegrityEngine` | `test_typosquat_distance_1_raises_high` |
| Unicode homoglyph shadowing | T6-002 | ✅ Done | `IntegrityEngine` | `test_nfkc_homoglyph_shadowing_detected` |
| Duplicate tool name in manifest | T6-003 | ✅ Done | `IntegrityEngine` | `test_regression_duplicate_ascii_name_raises_shadowing` |
| Mid-session manifest drift (rug pull) | T6-004 | ✅ Done | `IntegrityEngine` | `test_drift_detected_when_hash_changes` |
| Missing `name` field in manifest | T6-005 | ✅ Done | `IntegrityEngine` | `test_regression_missing_name_key_raises` |
| Session fixation | T7-001 | ✅ Done | `SessionEngine` | `test_unknown_session_id_rejected` |
| Session ID in URL params | T7-002 | ✅ Done | `SessionEngine` | `test_session_id_in_url_params_rejected` |
| Percent-encoded URL key bypass | T7-003 | ✅ Done | `ArmorMiddleware` | `test_regression_session_id_url_encoded_key_rejected` |
| Cross-transport replay | T7-004 | ✅ Done | `SessionEngine` | `test_transport_change_rejected` |
| Fabricated session_id on initialize | T7-005 | ✅ Done | `SessionEngine` | `test_initialize_also_checks_session_is_known` |
| Context bleed after session close | T7-006 | ✅ Done | `SessionEngine` | `test_session_cleared_on_end` |
| Session resource leak | T7-007 | ✅ Done | `_GuardedToolDispatcher` | `test_regression_close_session_fires_when_run_request_raises` |
| CORS wildcard on MCP endpoint (T07-001/G-02) | T7-008 | ✅ Done | `ArmorMiddleware` | `test_cors_disallowed_origin_rejected`, `test_cors_empty_allowlist_blocks_all_cross_origin` |
| Server bound to 0.0.0.0 | T8-001 | ✅ Done | `NetworkEngine` | `test_wildcard_bind_rejected` |
| SSRF to loopback | T8-002 | ✅ Done | `NetworkEngine` | `test_loopback_is_ssrf_target` |
| SSRF to RFC1918 | T8-003 | ✅ Done | `NetworkEngine` | `test_rfc1918_10_is_ssrf_target` |
| SSRF to link-local | T8-004 | ✅ Done | `NetworkEngine` | `test_link_local_is_ssrf_target` |
| LLM output injection pattern | T9-001 | ✅ Done | `TrustEngine` | `test_sanitize_injection_pattern_raises` |
| Surrogate characters | T9-002 | ✅ Done | `TrustEngine` | `test_sanitize_surrogate_chars_stripped` |
| XSS via unsanitized output | T9-003 | ✅ Done | `TrustEngine` | `test_sanitize_html_escapes_output` |
| Control characters in output | T9-004 | ✅ Done | `TrustEngine` | `test_sanitize_control_chars_removed` |
| Dual-encoding bypass | T9-005 | ✅ Done | `_GuardedToolDispatcher` | `test_regression_guarded_tool_raw_body_is_html_escaped` |
| Unbounded call count | T10-001 | ✅ Done | `ResourceEngine` | `test_call_budget_exceeded_raises` |
| Wall-clock time exhaustion | T10-002 | ✅ Done | `ResourceEngine` | `test_wall_clock_exceeded_raises` |
| Recursive tool call loops | T10-003 | ✅ Done | `ResourceEngine` | `test_loop_depth_exceeded_raises` |
| Rate limit visible at HTTP layer (T10-004/H-03) | T10-004 | ✅ Done | `ArmorMiddleware` | `test_resource_exceeded_returns_http_429`, `test_resource_exceeded_retry_after_header_value` |
| Unlisted tool loaded | T11-001 | ✅ Done | `SupplyChainEngine` | `test_unlisted_tool_denied` |
| Typosquatted tool (d≤threshold) | T11-002 | ✅ Done | `SupplyChainEngine` | `test_typosquat_within_threshold_denied` |
| Unicode homoglyph in tool name | T11-003 | ✅ Done | `SupplyChainEngine` | `test_nfkc_typosquat_within_threshold_denied` |
| Tampered registry signature | T11-004 | ✅ Done | `SupplyChainEngine` | `test_ed25519_wrong_signature_denied` |
| Malformed hex signature | T11-005 | ✅ Done | `SupplyChainEngine` | `test_regression_bad_hex_sig_raises_supply_chain_error` |
| Tampered audit log (chain break) | T12-001 | ✅ Done | `AuditEngine` | `test_tampered_entry_detected` |
| Raw PII in audit params | T12-002 | ✅ Done | `AuditEngine` | `test_params_logged_as_digest_not_raw` |

---

## Known Limitations

These are deliberate design choices, not bugs.

**T4 / T5 / T9 — response engines block, they do not scrub.** When PII, a secret, or an
injection pattern is detected in a tool response, the **entire** response is blocked: an
opaque error replaces the whole body. The engines do not redact, strip, or sanitize content
in place and forward it. The only in-place redaction is `TrustEngine.sanitize()`, which is
an explicit operator call — not part of the automatic response path. Scrub-and-forward
redaction support is planned for a future release.

**T6 — drift detection is per-call-chain only on the HTTP adapter.** `ArmorMiddleware`
creates a fresh `CoSAIContext` per HTTP request and does not restore session state between
requests, so `IntegrityEngine`'s mid-session rug-pull detection (T6-001) cannot fire
across separate HTTP round-trips. It works correctly within a single call chain. All other
T6 checks (allowlist, typosquat, homoglyph, shadow) fire on every `tools/list` response.
Fix planned; see [SECURITY.md](SECURITY.md#known-limitations) for the full write-up.

**T10 — heartbeat reaper active as of v0.2.0.** The background zombie-session reaper is
now started in `ResourceEngine.on_startup()`. Sessions with no activity for
`heartbeat_interval_secs` are evicted and the `ArmorMiddleware` session map is cleaned
via the `eviction_callback` hook. Active sessions remain bounded by `max_wall_clock_secs`
in addition to the heartbeat.

**TypeScript / non-Python servers.** mcp-armor is a Python library. For TypeScript or
other language servers, use the HTTP sidecar proxy pattern described in
[TYPESCRIPT.md](TYPESCRIPT.md).

---

## Hardening Changes (v0.2.0)

The 19 fixes shipped in commit `9caf11c` hardened existing engines without changing their
external API. All coverage matrix entries remain Done. What changed internally:

### AuditEngine (T12)
- File I/O dispatched via `asyncio.to_thread` — the event loop is never blocked.
- `asyncio.Lock` wraps seq-assignment + disk write atomically, fixing a concurrent-write
  race that could produce duplicate `prev_hash` values under load.
- HMAC signing: set `ARMOR_AUDIT_HMAC_KEY` (64-char hex / 32 bytes) to add an
  unforgeable `chain_hmac` field to every record, closing the log-truncation-and-
  recalculation gap in pure SHA-256 chaining. As of v1.1.0 this key is **required** at
  startup when T12 is enabled (`T12.require_hmac_key` defaults to `true`); opt out for dev
  only with `require_hmac_key: false` or `ARMOR_AUDIT_ALLOW_UNSIGNED=1`.
- `ARMOR_AUDIT_HMAC_KEY_PREV` supports zero-downtime key rotation: old records verified
  with the previous key are accepted with a WARNING.
- `.hmac_enabled` sticky marker file: once HMAC is written, startup rejects a missing
  key rather than silently downgrading integrity protection.
- HMAC key validated at `__init__` (not per-record); invalid hex raises `ConfigError` at
  startup.

### Audit chain — rollback-to-empty closed (v1.1.0)
- Deleting the audit log while the `.hwm` sidecar or the `.hmac_enabled` marker survives now
  raises `AuditChainError` at startup. An attacker can no longer reset the chain to an empty
  state to erase prior history.

### BoundaryEngine (T4)
- Normalization pipeline added before pattern matching: whitespace collapse, zero-width
  char stripping, bidi override char stripping, intra-word hyphen removal, NFKC, and
  Base64 decode-and-rescan. Closes split-word / invisible-char / encoded bypasses.
- Base64 loop capped at 8 token matches and 512 decoded chars per call — CPU DoS guard.

### ResourceEngine (T10)
- Background heartbeat reaper now actually starts: `on_startup()` creates the task via
  `asyncio.get_running_loop().create_task()`. Previously the task was never launched and
  the T10-004 limitation in Known Limitations applied; that limitation is now resolved.
- Eviction callback wired to `ArmorMiddleware._active_sessions` so zombie session eviction
  also cleans the middleware's own session map.

### Guard / Context
- `@guard.protect(threats=[...])`: `AuthEngine` (T1) and `AuthzEngine` (T2) force-included
  regardless of the `threats=` filter — inadvertent auth bypass via `threats=["T3"]` is
  now impossible.
- `dry_run` mode: violations are logged at WARNING and audited as `"dry_run_violation"`
  events; `AuthorizationError` / `AuthenticationError` always re-raise even in dry_run.
  Activated via `CoSAIGuard(dry_run=True)` or `dry_run: true` in `cosai.yaml`.
  `NOT FOR PRODUCTION`.
- `@guard.protect` now reads `_active_ctx` ContextVar set by the ASGI adapter, so
  decorated tools see the live CoSAIContext with real JWT scopes during HTTP requests.
- ContextVar reset via token in `finally` block — no context bleed between requests.
- `_GuardedToolDispatcher` sets `_active_ctx` — FastMCP adapter now propagates context
  the same way as the ASGI adapter.

### Config
- `load_config()` emits a WARNING log immediately when `dry_run: true` is parsed.
- `asyncio.get_event_loop()` replaced with `asyncio.get_running_loop()` throughout —
  avoids the deprecated API and the wrong-loop bug in coroutine context.

---

## Hardening Changes (v1.1.0 — audit remediation)

### ValidationEngine (T3) — schema enforcement now LIVE
- JSON-Schema validation is enforced on the adapter path. Each tool's `inputSchema`
  auto-registers from the observed `tools/list` response (`ValidationEngine.on_response`);
  operators do **not** call `register_tool_schemas()` manually. A schema-valid `tools/call`
  passes; a violation is rejected with JSON-RPC `-32602`. Previously the schema check was
  defined but never invoked (a latent self-DoS).

### SessionEngine (T7) — transport continuity only
- T7 enforces transport-bound session **continuity** (a session on one transport cannot be
  replayed over another). The former `bind_session_to_dpop` / `bind_to_dpop` flag was
  removed and is now an unknown config key. DPoP sender-constraint (proof-of-possession) is
  enforced at **T1** by `AuthEngine` via the access token's `cnf.jkt` claim, not by T7.

### NetworkEngine (T8) — startup bind check wired
- The startup public-bind check is wired via T8 config keys `bind_host` / `bind_port`. When
  `bind_host` is set, `guard.startup()` raises `NetworkBindingError` on a public bind (e.g.
  `0.0.0.0`) unless `allow_public_bind: true`. Per-request SSRF inspection is always on.

### SupplyChainEngine (T11) — registry signatures stay opt-in
- Ed25519 registry-signature verification remains **opt-in** (`require_registry_signature`
  defaults to `false`). Only the T12 audit-chain HMAC key is mandatory by default.

---

## Running the test suite

```bash
# Full suite (unit + adapter + adversarial):
pytest tests/ -q

# Adversarial integration tests only:
pytest tests/adversarial/ -v

# Security regression tests only:
pytest tests/ -q -k "regression"

# With coverage gate (CI enforces 88%):
pytest tests/ --cov=mcp_armor --cov-fail-under=88
```

## Adversarial integration suite

`tests/adversarial/test_integration.py` (50 tests) covers six areas the Codex review
identified as integration-coverage gaps:

| Area | Tests | What is asserted |
|------|-------|-----------------|
| Response blocking (Finding 1) | 7 | SSN / JWT / API key / CC / prompt injection in upstream response — client gets opaque error, sensitive body absent from reply |
| `tools/list` enforcement (Finding 2) | 8 | Unallowlisted, typosquatted, homoglyph, duplicate, and unsigned manifests blocked through middleware and dispatcher; drift detection tested within a single call chain (see Known Limitations) |
| SSRF via `tools/call` (Finding 3) | 9 | RFC1918 / loopback / link-local / localhost URLs in arguments blocked; public IPs pass |
| `tool_allowlist` config semantics (Finding 4) | 6 | `[]` blocks all; `None` allows all; named list is exact-match |
| Malformed JSON-RPC fuzz (Finding 6) | 11 | `[]`, `null`, `"string"`, `1`, `true`, batch, non-JSON, wrong Content-Type, oversized body, params-as-array — all return JSON-RPC errors |
| Docs/API contract (Finding 4 + general) | 9 | `CoSAIGuard.default()` composition, `scan_responses=False`, `scan_call_args=False`, `required_scope`, PII profile semantics |
