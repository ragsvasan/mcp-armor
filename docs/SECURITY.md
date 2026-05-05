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

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (current) | Yes |
| < 0.1 | No |
