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

## Known Limitations

The following are known limitations, not vulnerabilities. They are documented here for transparency and tracked in [docs/COVERAGE.md](COVERAGE.md).

1. **AuditEngine race condition (issue #1):** `_prev_hash` is read outside the lock in `_write()`. Under high concurrency, two threads could produce entries with the same `prev_hash`, breaking the chain. Fix in Phase 1.

2. **ProtectionEngine blocks, does not redact:** When PII is detected in a tool response, the response is blocked entirely. It is not scrubbed/redacted and forwarded. This is a conservative choice — some deployments may need redaction instead of blocking.

3. **RE2 fallback (partially mitigated):** If `google-re2` is not installed, mcp-armor falls back to stdlib `re`. `BoundaryEngine._scan()` truncates strings to 8,192 chars before pattern matching to bound worst-case time, but this is defence-in-depth, not a complete fix. Install `google-re2` in production for linear-time guarantees.

4. **IntegrityEngine drift detection is per-call-chain only (HTTP adapter):** `ArmorMiddleware` creates a fresh `CoSAIContext` for each HTTP request and does not restore session context between requests. As a result, `IntegrityEngine`'s mid-session drift detection (T6-001 — rug-pull) does not fire across separate HTTP round-trips; the manifest hash accumulated in one request's ctx is not visible to the next. Drift detection works correctly within a single call chain (e.g. `wrap_dispatcher` where the same ctx is threaded through, or a long-running streaming session). Fix planned: persist and restore ctx in `_active_sessions` across requests. Workaround: call `register_tool_schemas()` at startup to snapshot the baseline manifest — supply chain and integrity checks still fire on every `tools/list` response for allowlist, typosquat, homoglyph, and shadow violations.

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

By default, the T12 audit chain uses SHA-256 hash chaining.  This detects
in-place field tampering but does NOT prevent a sophisticated attacker who has
write access to the log from truncating it and recalculating all chain hashes
from scratch — erasing evidence without detection.

**To close this gap, set the `ARMOR_AUDIT_HMAC_KEY` environment variable** to a
hex-encoded 32+ byte secret (generate with `python -c "import secrets; print(secrets.token_hex(32))"`).

When set, every audit record gains a `chain_hmac` field computed as
`HMAC-SHA256(key, canonical_JSON_bytes)`.  Recalculating the chain after
truncation without the key is computationally infeasible.

Store the key in your secret manager (Vault, AWS Secrets Manager, GCP Secret
Manager, etc.).  **Do not store it in `cosai.yaml` or source control.**

**Production deployments MUST set `ARMOR_AUDIT_HMAC_KEY`.**

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (current) | Yes |
| < 0.1 | No |
