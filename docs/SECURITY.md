# mcp-armor — Security Policy

## Reporting Vulnerabilities

**Do not file public GitHub issues for security vulnerabilities.**

Report vulnerabilities via GitHub's private security advisory feature:  
`https://github.com/ragsvasan/mcp-armor/security/advisories/new`

Include:
- Description of the vulnerability
- Affected versions
- Steps to reproduce
- Potential impact
- Suggested fix (if known)

Expected response time: 48 hours for acknowledgement, 7 days for initial assessment.

---

## Scope

In scope:
- Security bypasses in any of the 12 protection engines
- False negatives: mcp-armor fails to detect/block a CoSAI threat
- Authentication or session vulnerabilities in the engine chain
- Race conditions in the audit log (T12)
- Injection vulnerabilities in the config loader
- Any issue that allows an attacker to bypass or disable a protection engine

Out of scope:
- Vulnerabilities in frameworks that mcp-armor wraps (FastAPI, FastMCP) — report those upstream
- Vulnerabilities in the underlying Python runtime
- Social engineering

---

## Security Design Principles

**Fail closed.** Every engine raises a `CoSAIException` subclass on violation. There is no logging-only mode by default. Unhandled exceptions in the engine chain abort the request.

**No code execution in config.** `cosai.yaml` is a data file. It cannot execute Python, shell commands, or templates. Template substitution (if added) will be restricted to a fixed allowlist of variables.

**Immutability.** All request/response types are frozen dataclasses. Engines cannot mutate shared state — they return new context objects. This eliminates a class of TOCTOU bugs.

**Escape at ingestion.** `MCPResponse.raw_body` is HTML-escaped (`html.escape(quote=True)`) when the object is created. All downstream consumers receive pre-escaped content. This prevents the class of bugs where content passes through multiple code paths before escaping is applied.

**RE2 for all regex.** All pattern matching uses `google-re2` (linear time, no backtracking). Catastrophic backtracking on attacker-controlled input is a DoS vector. Stdlib `re` is used as a fallback for development only — production deployments must have `google-re2` installed.

**Audit log integrity.** The T12 audit log is hash-chained (SHA-256). Tampering with any entry breaks the chain at the next entry. File-level append-only enforcement (`chattr +a` on Linux) is the server operator's responsibility — document that this is not enforced by the library.

---

## Destructive Tool Gate — Known Limitations

The `T2` destructive-tool gate (`destructive: true` in `tool_policies`) uses a
two-stage commit pattern: the first call returns an error with a one-time
confirmation token; the second call re-submits with that token.

**This gate has an irresolvable paradox depending on the `echo_confirm_token` setting:**

### `echo_confirm_token: false` (default)
The confirmation token is written to the server log at `WARNING` level and is
**not** returned in the client-facing error body.  A human operator can retrieve
the token out-of-band and re-submit on behalf of the caller.

**Problem:** clients that cannot read server logs (the overwhelming majority of
LLM agent deployments) have no way to complete the two-stage flow — the gate
is effectively broken for them.

### `echo_confirm_token: true`
The confirmation token **is** returned in the JSON-RPC error body.  Any client
that can read its own error messages can complete the flow.

**Problem:** autonomous LLM agents can and will parse the token from the error
response and auto-resubmit it on the very next call, completing the two-stage
flow without any human involvement — fully defeating the gate.

### Conclusion

**The destructive tool gate is only meaningful for deployments where the client
routes the error response through a human approval step BEFORE the token reaches
the agent.** For example:
- A UI that intercepts the `AuthorizationError`, shows an "Are you sure?" dialog
  to the user, and only forwards the token to the agent after human approval.
- An RFC 9470 step-up authentication challenge that requires a second factor.
- An out-of-band approval workflow (e.g. a Slack approval bot) triggered by the
  server log token.

**For fully autonomous agent clients with no human-in-the-loop intercept, this
gate provides no protection regardless of the `echo_confirm_token` setting.**

---

## Audit Log HMAC Signing

By default, the T12 audit chain uses SHA-256 hash chaining. This detects in-place field
tampering but does NOT prevent a sophisticated attacker who has write access to the log
from truncating it and recalculating all chain hashes from scratch — erasing evidence
without detection.

**To close this gap, set the `ARMOR_AUDIT_HMAC_KEY` environment variable** to a
hex-encoded 32-byte (64-character hex) secret.

Generate a key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
# or
openssl rand -hex 32
```

When set, every audit record gains a `chain_hmac` field computed as
`HMAC-SHA256(key, canonical_JSON_bytes)`. Recalculating the chain after truncation
without the key is computationally infeasible.

**Key validation:** The key is parsed to bytes at `AuditEngine.__init__`. If the value
is not valid hex, `ConfigError` is raised at startup — the server will not start with a
misconfigured key.

Store the key in your secret manager (Vault, AWS Secrets Manager, GCP Secret Manager,
etc.). **Do not store it in `cosai.yaml` or source control.**

**Production deployments MUST set `ARMOR_AUDIT_HMAC_KEY`.**

---

## HMAC Key Rotation

To rotate the HMAC key with zero downtime:

1. Set `ARMOR_AUDIT_HMAC_KEY_PREV` to the current (old) key.
2. Set `ARMOR_AUDIT_HMAC_KEY` to the new key.
3. Deploy — new records are signed with the new key; old records are verified against
   the previous key with a WARNING log.
4. Once all old records are re-verified (or the log is rotated), unset
   `ARMOR_AUDIT_HMAC_KEY_PREV`.

**Do not skip the `PREV` step.** Setting a new key without retaining the old one in
`PREV` causes chain verification to fail on every existing record.

---

## HMAC Sticky Marker

When `ARMOR_AUDIT_HMAC_KEY` is set on first startup, mcp-armor creates a sidecar file
`<audit_log_path>.hmac_enabled`. On subsequent startups, if this marker exists but
`ARMOR_AUDIT_HMAC_KEY` is absent, startup raises `AuditChainError` rather than silently
downgrading integrity protection.

This prevents an attacker who gains access to the server's environment from disabling
HMAC by unsetting the env var.

To intentionally downgrade (not recommended — treat as a security event): remove the
`.hmac_enabled` sidecar file and document the reason.

---

## `dry_run` Mode

`CoSAIGuard` supports a `dry_run` mode for configuration tuning:

```python
guard = CoSAIGuard(engines, dry_run=True)
# or in cosai.yaml:
# dry_run: true
```

When active:
- Security violations are caught, logged at `WARNING`, and audited as `"dry_run_violation"` events.
- The request proceeds as if no violation occurred.
- `AuthorizationError` and `AuthenticationError` always re-raise even in dry_run — auth is
  never suppressed.
- A WARNING is logged at guard construction time and at config load time.

**`dry_run: true` is NOT FOR PRODUCTION.** It disables all enforcement except auth.
Use it only for testing and configuration tuning in non-production environments.

---

## Known Limitations

The following are known limitations, not vulnerabilities. They are documented here for transparency and tracked in [docs/COVERAGE.md](COVERAGE.md).

1. **ProtectionEngine blocks, does not redact:** When PII is detected in a tool response, the response is blocked entirely. It is not scrubbed/redacted and forwarded. This is a conservative choice — some deployments may need redaction instead of blocking.

2. **RE2 fallback (partially mitigated):** If `google-re2` is not installed, mcp-armor falls back to stdlib `re`. `BoundaryEngine._scan()` truncates strings to 8,192 chars before pattern matching to bound worst-case time, but this is defence-in-depth, not a complete fix. Install `google-re2` in production for linear-time guarantees.

3. **IntegrityEngine drift detection is per-call-chain only (HTTP adapter):** `ArmorMiddleware` creates a fresh `CoSAIContext` for each HTTP request and does not restore session context between requests. As a result, `IntegrityEngine`'s mid-session drift detection (T6-001 — rug-pull) does not fire across separate HTTP round-trips; the manifest hash accumulated in one request's ctx is not visible to the next. Drift detection works correctly within a single call chain (e.g. `wrap_dispatcher` where the same ctx is threaded through, or a long-running streaming session). Fix planned: persist and restore ctx in `_active_sessions` across requests. Workaround: call `register_tool_schemas()` at startup to snapshot the baseline manifest — supply chain and integrity checks still fire on every `tools/list` response for allowlist, typosquat, homoglyph, and shadow violations.

---

## Destructive Tool Gate — Known Limitations

The `T2` destructive-tool gate (`destructive: true` in `tool_policies`) uses a
two-stage commit pattern: the first call returns an error with a one-time
confirmation token; the second call re-submits with that token.

**This gate has an irresolvable paradox depending on the `echo_confirm_token` setting:**

### `echo_confirm_token: false` (default)
The confirmation token is written to the server log at `WARNING` level and is
**not** returned in the client-facing error body.  A human operator can retrieve
the token out-of-band and re-submit on behalf of the caller.

**Problem:** clients that cannot read server logs (the overwhelming majority of
LLM agent deployments) have no way to complete the two-stage flow — the gate
is effectively broken for them.

### `echo_confirm_token: true`
The confirmation token **is** returned in the JSON-RPC error body.  Any client
that can read its own error messages can complete the flow.

**Problem:** autonomous LLM agents can and will parse the token from the error
response and auto-resubmit it on the very next call, completing the two-stage
flow without any human involvement — fully defeating the gate.

### Conclusion

**The destructive tool gate is only meaningful for deployments where the client
routes the error response through a human approval step BEFORE the token reaches
the agent.** For example:
- A UI that intercepts the `AuthorizationError`, shows an "Are you sure?" dialog
  to the user, and only forwards the token to the agent after human approval.
- An RFC 9470 step-up authentication challenge that requires a second factor.
- An out-of-band approval workflow (e.g. a Slack approval bot) triggered by the
  server log token.

**For fully autonomous agent clients with no human-in-the-loop intercept, this
gate provides no protection regardless of the `echo_confirm_token` setting.**

---

## Production Checklist

Required before deploying mcp-armor in production:

| # | Requirement | How |
|---|-------------|-----|
| 1 | Set `ARMOR_AUDIT_HMAC_KEY` | `python -c "import secrets; print(secrets.token_hex(32))"` — store in secret manager |
| 2 | Do NOT set `dry_run: true` | Remove or set `dry_run: false` in `cosai.yaml` |
| 3 | Install `google-re2` | `pip install google-re2` — linear-time regex, no catastrophic backtracking |
| 4 | Set `T12.chain_verify_on_startup: true` | Default — ensures startup raises on tampered log |
| 5 | Use `cors_origins=["https://your-domain.com"]` | Never use `"*"` on MCP endpoints |
| 6 | Understand `echo_confirm_token` tradeoff | Default `false` is safer for autonomous agents; `true` required for fully automated clients |
| 7 | Tune `heartbeat_interval_secs` | Default 30s; reduce for high-churn workloads |
| 8 | Set `ARMOR_AUDIT_HMAC_KEY_PREV` during key rotation | Never rotate without keeping the previous key in `PREV` during the grace period |

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x (current) | Yes |
| 0.1.x | Yes (security fixes backported) |
| < 0.1 | No |
