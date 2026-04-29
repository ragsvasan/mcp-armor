# CoSAI MCP Threat Remediation Guide

This document maps each CoSAI MCP threat category (T1–T12) to the mcp-armor
engine that remediates it, the specific attack vector addressed, and the
verification test that proves the control works.

---

## T1 — Authentication Failures

| Attack vector | Engine | Verification |
|---|---|---|
| Missing or unsigned JWT | `AuthEngine` | `test_missing_token_rejected` |
| `alg: none` JWT downgrade | `AuthEngine` | `test_none_algorithm_rejected` |
| Replayed JTI (token reuse) | `AuthEngine` | `test_jti_replay_rejected` |
| DPoP binding absent or wrong key | `AuthEngine` | `test_dpop_wrong_key_rejected` |
| Weak RSA key (< 2048 bit) | `AuthEngine` | `test_dpop_weak_rsa_key_rejected` |

**Standard**: RFC 9449 (DPoP), RFC 7519 (JWT), OWASP API Security A02.

---

## T2 — Authorization Failures (RBAC, Confused Deputy, Tenant Isolation)

| Attack vector | Engine | Verification |
|---|---|---|
| Tool call without required scope | `AuthzEngine` | `test_missing_required_scope_denied` |
| Server-to-server call to user-only tool | `AuthzEngine` | `test_user_only_tool_without_user_denied` |
| Cross-tenant argument forgery | `AuthzEngine` | `test_tenant_isolated_mismatched_tenant_denied` |
| `tenant_id` absent from arguments | `AuthzEngine` | `test_regression_tenant_isolated_no_arg_tenant_denied` |
| Destructive tool without confirm token | `AuthzEngine` | `test_destructive_tool_no_token_denied` |
| Confirm token reuse (single-use) | `AuthzEngine` | `test_destructive_token_single_use` |
| Token cross-tool replay | `AuthzEngine` | `test_regression_confirm_token_not_transferable_across_tools` |
| Timing oracle via self-referential compare | `AuthzEngine` | `test_regression_dummy_compare_uses_fixed_length_secret` |

**Standard**: OWASP API Security A01, A05; CoSAI CodeGuard §Destructive Tools.

---

## T3 — Input Validation

| Attack vector | Engine | Verification |
|---|---|---|
| Oversized payload (denial of wallet) | `ValidationEngine` | `test_oversized_payload_rejected` |
| Shell metacharacters in arguments | `ValidationEngine` | `test_shell_injection_in_args_rejected` |
| Path traversal (`../../etc/passwd`) | `ValidationEngine` | `test_path_traversal_in_args_rejected` |
| SQL injection (`UNION SELECT`) | `ValidationEngine` | `test_sql_injection_in_args_rejected` |

---

## T4 — Data/Control Boundary (Prompt Injection)

| Attack vector | Engine | Verification |
|---|---|---|
| "Ignore previous instructions" in args | `BoundaryEngine` | `test_owasp_a01_ignore_previous_instructions` |
| Role-override preamble ("you are now") | `BoundaryEngine` | `test_owasp_a04_you_are_now` |
| System prompt reveal attempt | `BoundaryEngine` | `test_owasp_a06_system_prompt` |
| Injection in tool response body | `BoundaryEngine` | `test_injection_in_response_raises` |
| Nested dict injection (indirect) | `BoundaryEngine` | `test_nested_dict_injection_detected` |
| Injection in tool name field | `BoundaryEngine` | `test_regression_injection_in_tool_name_param_detected` |

**Standard**: OWASP LLM Top 10 A01 (Prompt Injection).

---

## T5 — Inadequate Data Protection (PII Leak)

| Attack vector | Engine | Verification |
|---|---|---|
| SSN in tool response | `ProtectionEngine` | `test_ssn_in_response_blocked_pci` |
| Credit card number in response | `ProtectionEngine` | `test_credit_card_in_response_blocked_pci` |
| JWT token exposed in response | `ProtectionEngine` | `test_jwt_in_response_blocked_pci` |
| API key in response | `ProtectionEngine` | `test_api_key_in_response_blocked_pci` |
| Email (GDPR-regulated) in response | `ProtectionEngine` | `test_email_in_response_blocked_strict` |

**Standard**: PCI DSS v4, HIPAA § 164.312, GDPR Art. 5.

---

## T6 — Tool Integrity Failures

| Attack vector | Engine | Verification |
|---|---|---|
| Typosquatted tool name (d=1) | `IntegrityEngine` | `test_typosquat_distance_1_raises_high` |
| Unicode homoglyph shadowing | `IntegrityEngine` | `test_nfkc_homoglyph_shadowing_detected` |
| Duplicate tool name in manifest | `IntegrityEngine` | `test_regression_duplicate_ascii_name_raises_shadowing` |
| Tool manifest drift mid-session (rug pull) | `IntegrityEngine` | `test_drift_detected_when_hash_changes` |
| Missing `name` field in manifest | `IntegrityEngine` | `test_regression_missing_name_key_raises` |

---

## T7 — Session Security Failures

| Attack vector | Engine | Verification |
|---|---|---|
| Session fixation (attacker-chosen ID) | `SessionEngine` | `test_unknown_session_id_rejected` |
| Session ID in URL query params (Referer leak) | `SessionEngine` | `test_session_id_in_url_params_rejected` |
| Session ID in percent-encoded URL key | `ArmorMiddleware` | `test_regression_session_id_url_encoded_key_rejected` |
| Cross-transport replay (HTTP token on stdio) | `SessionEngine` | `test_transport_change_rejected` |
| `initialize` with fabricated session_id | `SessionEngine` | `test_initialize_also_checks_session_is_known` |
| Context bleed after session close | `SessionEngine` | `test_session_cleared_on_end` |
| Session resource leak (no close_session) | `_GuardedToolDispatcher` | `test_regression_close_session_fires_when_run_request_raises` |

**Standard**: OWASP Session Management Cheat Sheet, MCP spec §3.4.

---

## T8 — Network Binding Failures (SSRF)

| Attack vector | Engine | Verification |
|---|---|---|
| Server bound to 0.0.0.0 | `NetworkEngine` | `test_wildcard_bind_rejected` |
| SSRF to loopback (127.x.x.x) | `NetworkEngine` | `test_loopback_is_ssrf_target` |
| SSRF to RFC1918 (10.x, 172.16.x, 192.168.x) | `NetworkEngine` | `test_rfc1918_10_is_ssrf_target` |
| SSRF to link-local (169.254.x) | `NetworkEngine` | `test_link_local_is_ssrf_target` |

**Standard**: OWASP SSRF Prevention Cheat Sheet, RFC 1918.

---

## T9 — Trust Boundary Violations (LLM Output)

| Attack vector | Engine | Verification |
|---|---|---|
| LLM output contains injection pattern | `TrustEngine` | `test_sanitize_injection_pattern_raises` |
| Surrogate characters (Unicode attacks) | `TrustEngine` | `test_sanitize_surrogate_chars_stripped` |
| XSS via unsanitized LLM output | `TrustEngine` | `test_sanitize_html_escapes_output` |
| Control characters in output | `TrustEngine` | `test_sanitize_control_chars_removed` |
| Dual-encoding bypass (html.escape skipped) | `_GuardedToolDispatcher` | `test_regression_guarded_tool_raw_body_is_html_escaped` |

---

## T10 — Resource Management (Denial of Wallet)

| Attack vector | Engine | Verification |
|---|---|---|
| Unbounded call count | `ResourceEngine` | `test_call_budget_exceeded_raises` |
| Wall-clock time exhaustion | `ResourceEngine` | `test_wall_clock_exceeded_raises` |
| Recursive tool call loops | `ResourceEngine` | `test_loop_depth_exceeded_raises` |

---

## T11 — Supply Chain Attacks (Tool Poisoning)

| Attack vector | Engine | Verification |
|---|---|---|
| Unlisted tool loaded from registry | `SupplyChainEngine` | `test_unlisted_tool_denied` |
| Typosquatted tool name (d≤threshold) | `SupplyChainEngine` | `test_typosquat_within_threshold_denied` |
| Unicode homoglyph in tool name | `SupplyChainEngine` | `test_nfkc_typosquat_within_threshold_denied` |
| Tampered registry signature | `SupplyChainEngine` | `test_ed25519_wrong_signature_denied` |
| Malformed hex signature | `SupplyChainEngine` | `test_regression_bad_hex_sig_raises_supply_chain_error` |
| Non-FastMCP object injected via wrap_fastmcp | `wrap_fastmcp` | `test_regression_wrap_fastmcp_rejects_non_fastmcp_type` |

**Standard**: SLSA Level 2, Sigstore, Ed25519 (FIPS 186-5).

---

## T12 — Audit Logging

| Attack vector | Engine | Verification |
|---|---|---|
| Tampered audit log (chain break) | `AuditEngine` | `test_tampered_entry_detected` |
| Raw PII in audit params | `AuditEngine` | `test_params_logged_as_digest_not_raw` |

**Standard**: SOC 2 CC7.2, NIST SP 800-92.

---

## Integration Test Harness

The adversarial test harness in `tests/` validates the full guard chain end-to-end:

```bash
# Run the full adversarial suite:
pytest tests/ -q --tb=short

# Run only security-critical regression tests:
pytest tests/ -q -k "regression"

# Coverage gate (CI enforces 88%):
pytest tests/ --cov=mcp_armor --cov-fail-under=88
```

### Adding a new adversarial test

1. Identify the threat category and attack vector.
2. Add a `test_regression_<attack_name>` test in the corresponding
   `tests/engines/test_<engine>.py` file.
3. Verify the test fails without the fix and passes with it.
4. Add an entry to this table.
