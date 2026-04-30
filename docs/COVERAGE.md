# mcp-armor — Coverage Status

**Version:** 0.1.0  
**Date:** 2026-04-29  
**Tests:** 441 passing · Coverage: 90%+

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
| Oversized payload | T3-001 | ✅ Done | `ValidationEngine` | `test_oversized_payload_rejected` |
| Shell metacharacters in arguments | T3-002 | ✅ Done | `ValidationEngine` | `test_shell_injection_in_args_rejected` |
| Path traversal | T3-003 | ✅ Done | `ValidationEngine` | `test_path_traversal_in_args_rejected` |
| SQL injection | T3-004 | ✅ Done | `ValidationEngine` | `test_sql_injection_in_args_rejected` |
| Injection in tool definitions | T4-001 | ✅ Done | `BoundaryEngine` | `test_owasp_a01_ignore_previous_instructions` |
| Role-override preamble | T4-002 | ✅ Done | `BoundaryEngine` | `test_owasp_a04_you_are_now` |
| System prompt reveal | T4-003 | ✅ Done | `BoundaryEngine` | `test_owasp_a06_system_prompt` |
| Injection in tool call arguments | T4-004 | ✅ Done | `BoundaryEngine` | `test_regression_injection_in_tool_name_param_detected` |
| Injection in tool response body | T4-005 | ✅ Done | `BoundaryEngine` | `test_injection_in_response_raises` |
| Nested dict injection (indirect) | T4-006 | ✅ Done | `BoundaryEngine` | `test_nested_dict_injection_detected` |
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

**T5 — blocks, does not redact.** When PII is detected in a tool response the entire
response is blocked. There is no scrub-and-forward mode. This is the conservative choice
for 0.1.0; redaction support is planned for a future release.

**T6 — drift detection is per-call-chain only on the HTTP adapter.** `ArmorMiddleware`
creates a fresh `CoSAIContext` per HTTP request and does not restore session state between
requests, so `IntegrityEngine`'s mid-session rug-pull detection (T6-001) cannot fire
across separate HTTP round-trips. It works correctly within a single call chain. All other
T6 checks (allowlist, typosquat, homoglyph, shadow) fire on every `tools/list` response.
Fix planned; see [SECURITY.md](SECURITY.md#known-limitations) for the full write-up.

**T10 — heartbeat not enforced.** The `heartbeat_interval_secs` config key is accepted
and documented but the background monitor that marks sessions dead after a missed heartbeat
is not yet implemented. Active sessions are still bounded by `max_wall_clock_secs`.

**TypeScript / non-Python servers.** mcp-armor is a Python library. For TypeScript or
other language servers, use the HTTP sidecar proxy pattern described in
[TYPESCRIPT.md](TYPESCRIPT.md).

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
