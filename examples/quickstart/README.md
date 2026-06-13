# mcp-armor quickstart (runnable in 60 seconds)

A genuinely runnable config for a first look. **Dev only** — auth (T1), authz
(T2) and the supply-chain allowlist (T11) are disabled so you can drive the full
MCP flow without an IdP, a tool policy, or an allowlist. For a production posture
start from [`../../cosai.yaml.example`](../../cosai.yaml.example), which enables
all three and fails closed.

## 1. Set the one required env var

```bash
export ARMOR_SESSION_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))")
```

The T7 session signer fails closed without it (a per-process random key would
break multi-instance verification). T12 here uses an unsigned chain
(`require_hmac_key: false`) and a writable relative path, so no other setup is
needed.

## 2. Build the guard and wrap an app

```python
from mcp_armor import CoSAIGuard
from mcp_armor.adapters.fastapi import ArmorMiddleware

guard = CoSAIGuard.from_config("examples/quickstart/cosai.yaml")
app = ArmorMiddleware(your_asgi_mcp_app, guard)
```

## 3. Drive the MCP flow

`initialize` → `tools/list` → `tools/call`. The first `tools/list` response is
how T3 learns each tool's `inputSchema` (auto-registration); a subsequent
schema-valid `tools/call` passes, and a schema violation is blocked with
`-32602`.

```bash
# initialize → returns an Mcp-Session-Id header
curl -si localhost:8000/ -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

# reuse that session id on the next two calls
curl -s localhost:8000/ -H 'content-type: application/json' \
  -H 'mcp-session-id: <ID>' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

curl -s localhost:8000/ -H 'content-type: application/json' \
  -H 'mcp-session-id: <ID>' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}'
```

## Going to production

Switch to `cosai.yaml.example` and provide its documented prerequisites:
`ARMOR_SESSION_SECRET`, `ARMOR_AUDIT_HMAC_KEY`, a real JWKS + `endpoint_uri` for
T1, a `tool_allowlist` for T2/T11, and a writable T12 `path`. Run a single
worker (or a shared session store) for T6/T10 to hold across requests.
