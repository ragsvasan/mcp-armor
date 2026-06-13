# mcp-armor — Getting Started

## Prerequisites

- Python 3.11+
- An MCP server built on FastMCP, FastAPI, or a custom JSON-RPC dispatcher
- **`ARMOR_SESSION_SECRET`** — required for every deployment (dev and prod). The
  T7 session signer fails closed without it. Generate one:
  ```bash
  python -c "import secrets;print(secrets.token_hex(32))"
  ```

The **production** reference config (`cosai.yaml.example`) is fail-closed by
design and additionally requires the following before it will start — set them
all or the engine refuses to boot:

| Env var / config | Why required | How to provide |
|---|---|---|
| `ARMOR_SESSION_SECRET` | T7 session signing (any deployment) | `python -c "import secrets;print(secrets.token_hex(32))"` |
| `ARMOR_AUDIT_HMAC_KEY` | T12 `require_hmac_key` defaults `true` (audit A6); hex 32 bytes | `openssl rand -hex 32` |
| Real JWKS + `endpoint_uri` (config) | T1 `require_dpop: true` validates DPoP against your IdP | Point at your IdP's JWKS URL and the public endpoint URI |
| Writable T12 `path` (config) | Audit log file must be writable | Ensure the directory exists and is writable |

These env vars are read from the process environment — never put secrets in
`cosai.yaml` or source control.

## Install

```bash
pip install mcp-armor

# FastAPI / ASGI support
pip install mcp-armor[fastapi]

# Development (tests, linting, type checking)
pip install mcp-armor[dev]
```

Dependencies now carry **upper bounds**. For reproducible installs, generate a
hash-pinned lockfile yourself with `pip-compile --generate-hashes` — a shipped
lockfile is **not yet** included.

---

## 1. Fastest first run — the runnable quickstart

A genuinely runnable config boots on localhost with **one** env var:

```bash
export ARMOR_SESSION_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))")
```

```python
from mcp_armor import CoSAIGuard
from mcp_armor.adapters.fastapi import ArmorMiddleware

guard = CoSAIGuard.from_config("examples/quickstart/cosai.yaml")
app = ArmorMiddleware(your_asgi_mcp_app, guard)
```

Drive the full MCP flow — `initialize` → `tools/list` → `tools/call`. T3 learns
each tool's `inputSchema` automatically from the `tools/list` response
(`strict_schema` defaults `true` and now works end to end), so **no manual
schema registration is needed**: a schema-valid `tools/call` passes, and a
schema violation is rejected with JSON-RPC `-32602`.

See [`examples/quickstart/README.md`](../examples/quickstart/README.md) for the
full curl flow. The quickstart is **dev only** — T1/T2/T11 are disabled so you
can drive the flow without an IdP, tool policy, or allowlist.

---

## 2. Zero-Config Start

Sensible defaults, no config file (still requires `ARMOR_SESSION_SECRET`):

```python
from mcp_armor import CoSAIGuard

guard = CoSAIGuard.default()
app = guard.wrap(your_app)
```

This enables all 12 engines with conservative defaults. In production, use a `cosai.yaml` config file so policy is explicit, auditable, and checked in to version control.

---

## 3. Config File

Copy the example config and edit it for your deployment:

```bash
cp cosai.yaml.example cosai.yaml
```

Then load it:

```python
guard = CoSAIGuard.from_config("cosai.yaml")
app = guard.wrap(your_app)
```

The config is validated at load time. Unknown keys are rejected. The engine fails to start rather than silently ignoring misconfiguration.

---

## 4. FastAPI Integration

```python
from fastapi import FastAPI
from mcp_armor import CoSAIGuard
from mcp_armor.adapters.fastapi import ArmorMiddleware

app = FastAPI()
guard = CoSAIGuard.from_config("cosai.yaml")

app.add_middleware(
    ArmorMiddleware,
    guard=guard,
    cors_origins=["https://app.example.com"],  # restrict cross-origin access (T7-001)
)

@app.on_event("startup")
async def startup():
    await guard.startup()

@app.on_event("shutdown")
async def shutdown():
    await guard.shutdown()
```

`guard.startup()` runs the startup-only checks (T8 network binding, T11 supply chain). It must be called before the server begins accepting requests. If either check fails, the exception propagates and the server does not start — fail-closed.

**`cors_origins`** — set this to the list of origins allowed to make cross-origin requests to the MCP endpoint (T7-001 / cosai-mcp T07-001). Omitting it (default `None`) emits a startup warning. Use `cors_origins=[]` to block all cross-origin requests. Never use `"*"` — a CORS wildcard on the MCP endpoint allows any web page to make credentialed requests on behalf of an authenticated user.

**Rate limiting and HTTP 429** — `ResourceExceededError` (raised by `ResourceEngine` when a session's call budget is exhausted) returns HTTP 429 with a `Retry-After: 60` header rather than a JSON-RPC 200 error, so HTTP-layer rate limiters and security scanners can detect it (T10-004 / cosai-mcp T10-004).

---

## 5. Raw JSON-RPC Dispatcher

For custom transports or stdio servers:

```python
from mcp_armor import CoSAIGuard
from mcp_armor.adapters.dispatcher import wrap_dispatcher

guard = CoSAIGuard.from_config("cosai.yaml")

async def my_dispatcher(request: dict) -> dict:
    # Your MCP handler logic
    ...

protected = wrap_dispatcher(my_dispatcher, guard)

# In your server loop:
response = await protected(incoming_request)
```

---

## 5. Per-Tool Policy

Override the guard's default policy for individual tools:

```python
@app.tool()
@guard.protect(
    threats=["T3", "T5"],
    pii_profile="hipaa",          # stricter PII for this tool only
)
async def patient_lookup(mrn: str) -> dict:
    ...

@app.tool()
@guard.protect(
    threats=["T2", "T3"],
    required_scope="admin",       # T2: reject callers without admin scope
)
async def admin_reset() -> str:
    ...
```

Per-tool decorators are additive — the guard wrapper handles session-level concerns (T1, T7, T12), the decorator handles tool-level policy (T2, T3, T5).

---

## 6. Handle Security Exceptions

All security violations raise typed `CoSAIException` subclasses. Framework adapters translate these to JSON-RPC error responses automatically. If you need custom handling:

```python
from mcp_armor.exceptions import (
    AuthenticationError,
    InjectionDetectedError,
    ResourceExceededError,
    CoSAIException,
)

try:
    result = await protected(request)
except AuthenticationError:
    # 401 — log, notify, rate-limit the caller
    ...
except InjectionDetectedError as e:
    # 400 — alert security team
    logger.critical("Injection attempt", finding=e.finding)
    ...
except ResourceExceededError:
    # 429 — caller exceeded budget
    ...
except CoSAIException:
    # 500 — catch-all for unexpected violations
    ...
```

---

## 7. Read the Audit Log

The T12 `AuditEngine` writes a hash-chained JSON Lines file. Verify chain integrity:

```python
from mcp_armor.engines.audit import AuditEngine

engine = AuditEngine(path="/var/log/mcp-armor/audit.jsonl")
engine._verify_chain()  # raises AuditChainError if tampered
```

Each line is a JSON object with `session_id`, `user_id`, `method`, `params_digest` (never raw params), and chain hash fields. Feed into any log aggregator (Splunk, CloudTrail, Datadog) using JSON Lines ingestion.

---

## 8. Pair with cosai-mcp Scanner

mcp-armor (server-side) and cosai-mcp (black-box scanner) cover complementary parts of the threat surface:

```bash
# In CI: scan for protocol-layer vulnerabilities
pip install cosai-mcp
cosai-mcp scan http://localhost:8000 --fail-on critical
```

The scanner detects T1/T3/T8/T10 failures from outside. mcp-armor enforces T4/T9/T12 (and optionally all 12) from inside. Together they provide complete coverage.

---

## Threat Coverage at a Glance

| What you get | Threat |
|---|---|
| Auth header check, JTI replay detection, DPoP binding | T1 |
| Per-tool scope enforcement, confused deputy prevention | T2 |
| JSON schema strict mode, injection guards, size limit | T3 |
| 24 injection patterns — tool definitions + call args + response bodies, with normalization pipeline | T4 |
| PII scrubbing (5 profiles: minimal / pci / hipaa / gdpr / strict) | T5 |
| Manifest hash + drift detection, typosquatting check | T6 |
| Session fixation prevention, cross-transport replay block | T7 |
| Bind address check, SSRF prevention | T8 |
| LLM output sanitization — 5-step pipeline | T9 |
| Call budget, wall-clock limit, loop depth, active heartbeat reaper | T10 |
| Tool allowlist, registry Ed25519 signature check (opt-in) | T11 |
| HMAC-signed hash-chained JSON Lines audit log, DAG tracing | T12 |

---

## 9. Production Security Checklist

Before deploying mcp-armor to production, complete the following:

### 1. Set the HMAC audit key

Every production deployment must set `ARMOR_AUDIT_HMAC_KEY`. Without it, a sophisticated
attacker who gains write access to the log file can truncate it and recalculate all chain
hashes, erasing evidence without detection.

Generate a key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Store in your secret manager (Vault, AWS Secrets Manager, GCP Secret Manager). Set as an
environment variable — never in `cosai.yaml` or source control.

```bash
export ARMOR_AUDIT_HMAC_KEY=<64-char hex string>
```

Once set, the `.hmac_enabled` marker file prevents future deployments from accidentally
omitting the key. If you rotate the key, set `ARMOR_AUDIT_HMAC_KEY_PREV` to the old key
during the rotation grace period.

### 2. Never enable `dry_run: true` in production

`dry_run: true` (in `cosai.yaml` or `CoSAIGuard(dry_run=True)`) disables all enforcement.
Violations are logged but not blocked. Use it only for local configuration tuning.

As a guardrail, a guard with `dry_run=True` **will not even construct** unless
`ARMOR_ALLOW_DRY_RUN=1` is set in the environment — so it can never be enabled
by accident in an environment that does not explicitly opt in.

Check your config before deploying:
```bash
grep -i dry_run cosai.yaml
# Must be absent or 'dry_run: false'
```

### 3. Understand the `echo_confirm_token` tradeoff for destructive tools

For tools marked `destructive: true` in `tool_policies`, the two-stage commit gate issues
a confirmation token on the first call. The `echo_confirm_token` setting controls delivery:

- `echo_confirm_token: false` (default) — token written to server log only; automated
  clients cannot complete the flow.
- `echo_confirm_token: true` — token returned in the JSON-RPC error body; any client can
  complete the flow, including autonomous LLM agents that auto-resubmit it.

**The gate is only meaningful when a human intercepts the error before it reaches the
agent.** For fully autonomous pipelines with no human-in-the-loop, the gate provides no
protection regardless of this setting. See [SECURITY.md](SECURITY.md) for the full analysis.

### 4. Tune the heartbeat interval

`ResourceEngine` evicts zombie sessions (no activity within `heartbeat_interval_secs`).
The default is 30 seconds. For high-churn workloads, reduce it:

```yaml
threats:
  T10:
    heartbeat_interval_secs: 10   # evict faster
```

For long-running human-assisted sessions, increase it:
```yaml
    heartbeat_interval_secs: 120  # 2 minutes
```

---

## Configuration Reference

See [cosai.yaml.example](../cosai.yaml.example) for the full annotated configuration. Key options:

| Key | Default | Description |
|---|---|---|
| `T1.require_dpop` | `true` | Require DPoP proof-of-possession on every request |
| `T1.require_cnf_binding` | `true` | Under DPoP, require sender-constrained access tokens (`cnf.jkt`) — RFC 9449 §4.3. Rejects unbound tokens that a stolen-token replay could ride |
| `T2.default_policy` | `deny` | Deny tools not listed in `tool_policies` |
| `T3.max_payload_bytes` | `65536` | Maximum JSON-serialized params size |
| `T5.profile` | `pci` | PII detection profile |
| `T10.max_calls_per_session` | `100` | Hard cap on tool calls per session |
| `T10.max_wall_clock_secs` | `300` | Session time limit |
| `T12.path` | `/var/log/mcp-armor/audit.jsonl` | Audit log file path |

---

## Troubleshooting

**Server fails to start with `NetworkBindingError`**  
Your server is bound to `0.0.0.0`. Either change the bind address to `127.0.0.1`, or set `T8.allow_public_bind: true` in `cosai.yaml` (document the business reason for this override).

**All tool calls rejected with `AuthorizationError`**  
`T2.default_policy` is `deny` and no `tool_policies` are defined. Either add tool policies for each tool, or set `T2.default_policy: allow` (and accept the risk of no per-tool RBAC).

**`AuditChainError` on startup**  
The audit log chain is broken — either the file was truncated, lines were deleted, or the file was overwritten. Rotate to a new log file and investigate. Do not modify or delete the old file — it is evidence.

**`InjectionDetectedError` on legitimate tool responses**  
A legitimate tool response matched one of the 18 injection patterns. Review the specific pattern in `engines/boundary.py` and either: (a) sanitize the tool's response to remove the matching text, or (b) raise an issue if the pattern has a false positive — it may need tightening.
