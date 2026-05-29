# mcp-armor — Vision, Why & Use Cases

## The Problem

Every MCP security tool runs *against* servers. None run *inside* them.

Scanners (cosai-mcp, Cisco MCP Scanner) tell you which protocol-level vulnerabilities your server has. They are essential. But they cannot see inside the call path. They cannot detect whether tool responses contain prompt injection (T4), whether LLM-generated output is sanitized before re-feed (T9), or whether the agent's actions are being logged (T12). These three categories — which account for some of the most consequential attacks in practice — are structurally invisible from outside.

Middleware libraries (MCP-Bastion, mcp-authx) sit inside servers but cover 1–2 of the 12 CoSAI threat categories. A team that wants complete coverage has to assemble controls from multiple sources, with no guarantee the pieces interoperate or that coverage is honest.

The result: every team building on MCP is implementing security controls from scratch, inconsistently, with no way to verify the full-stack picture.

## What mcp-armor Is

mcp-armor is the **server-side complement** to the cosai-mcp scanner. Where the scanner probes from outside, mcp-armor enforces from inside. Together they cover all 12 CoSAI threat categories.

It ships three things:

**1. A composable engine chain**
Twelve engines, one per CoSAI threat category, assembled into a single `CoSAIGuard`. Drop it into any FastMCP or FastAPI server. One import, one wrap call.

**2. A typed policy layer**
`cosai.yaml` drives all 12 engines with validated, typed configuration. Per-tool policies, PII profiles, budget limits, allowlists — all in one file. Unknown keys rejected.

**3. Framework adapters**
FastMCP wrapper, ASGI middleware, raw JSON-RPC dispatcher wrapper. The core engines are framework-agnostic; adapters are thin translation layers.

## Design Principles

**Being in the call path is a feature, not a liability.** T4, T9, T12 are only addressable from inside the server. mcp-armor owns this position explicitly — the three-engine architecture docs make clear that no scanner can substitute for it.

**Fail closed.** Every engine raises a typed `CoSAIException` on violation. No silent ignoring. No logging-only mode by default. If a security check fails, the request does not proceed.

**Immutability throughout.** All result types are frozen dataclasses. All container fields are `tuple` or `MappingProxyType`. Context flows forward via `dataclasses.replace()`. No shared mutable state between requests.

**Honest about what's implemented.** The coverage matrix in COVERAGE.md distinguishes implemented, stub, and planned. A stub that raises `NotImplementedError` is preferable to code that silently does nothing.

**Composable, not monolithic.** `CoSAIGuard.default()` works out of the box. Per-tool decorators override policy at the tool level. Custom engine implementations can replace any built-in engine by implementing `ProtectionEngine`.

## Who This Is For

**MCP server authors** who want to protect their servers without building 12 security controls from scratch. The `guard.wrap(app)` call should take under an hour to integrate.

**Platform engineering teams** who want a consistent, auditable security baseline across all MCP servers in their fleet. The `cosai.yaml` config and SARIF-compatible findings make this audit-ready.

**Security engineers** who want to understand precisely which threats are covered, at which layer, by which mechanism. Every engine has a clear threat mapping. No magic.

---

## Use Cases

### 1. Protect a FastMCP server (< 10 minutes)

```python
from mcp_armor import CoSAIGuard
import fastmcp

app = fastmcp.FastMCP("my-server")
guard = CoSAIGuard.from_config("cosai.yaml")

@app.tool()
async def search(query: str) -> str:
    return db.search(query)

protected = guard.wrap(app)
```

Gives you: T1 auth checks, T3 input validation, T4 injection detection, T5 PII scrubbing, T10 budget enforcement, T12 audit logging — on every call.

---

### 2. Per-tool policies for mixed-sensitivity tools

```python
@app.tool()
@guard.protect(threats=["T3", "T5"], pii_profile="hipaa")
async def patient_lookup(mrn: str) -> dict: ...

@app.tool()
@guard.protect(threats=["T2", "T3"], required_scope="admin")
async def admin_reset() -> str: ...
```

Different tools have different risk profiles. mcp-armor lets you express that without forking your middleware stack.

---

### 3. Enterprise fleet baseline

The `cosai.yaml` config is checked into each server's repo. CI validates the config schema. The audit log path points to a centralised log aggregator. The same PII profile and budget limits apply uniformly across 50 internal MCP servers.

---

### 4. Pair with cosai-mcp for full coverage

```bash
# CI: scanner verifies protocol-layer controls
cosai-mcp scan http://localhost:8000 --fail-on critical

# Runtime: mcp-armor enforces call-path controls
# (T4, T9, T12 — structurally invisible to the scanner)
```

The scanner and mcp-armor cover different parts of the threat surface. Use both.

---

## Positioning vs. commercial platforms

CrowdStrike's *"AI Agent Security: A Practical 90-Day Roadmap for Securing Agentic AI"* defines an 8-workstream roadmap and sells its implementation as a closed Falcon module. mcp-armor (runtime enforcement) + [cosai-mcp](https://github.com/cosai-oasis/cosai-mcp) (CI-time proof) implement the same control set as OSS, anchored on cryptographic verification rather than vendor trust.

Honest status — *shipped* vs *roadmap*:

| # | CrowdStrike workstream | mcp-armor status |
|---|------------------------|------------------|
| 1 | Tool Inventory & Classification | Partial — per-tool `ToolPolicy` (scopes, `destructive`, `tenant_isolated`); roadmap: risk-tier + owner registry parse. |
| 2 | Auth, Identity & Version Control | **Shipped — exceeds:** `AuthEngine` (JWT+DPoP), `SessionEngine` transport binding, `SupplyChainEngine` Ed25519 + allowlist. |
| 3 | Prompt/Tool-Execution Guardrails | **Shipped — exceeds:** `BoundaryEngine` (24 OWASP patterns), `ValidationEngine`, `NetworkEngine` SSRF, RE2-only. |
| 4 | Observability for Planning & Tool Calls | Partial — `AuditEngine` hash-chained DAG log; **roadmap:** SIEM/SOAR emitter + anomaly thresholds. |
| 5 | Governance / Capability Drift | Partial — `IntegrityEngine` rug-pull detection; **roadmap:** approval-gate workflow + baseline registry. |
| 6 | Restrict Non-Human Identities | Partial — per-tool scopes, tenant isolation; **roadmap:** rotation enforcement + NHI anomaly monitor. |
| 7 | Human-in-the-Loop | Partial — `AuthzEngine` destructive token gate; **roadmap:** non-bypassable out-of-band approval (agent cannot resubmit its own token — current gap is a real security hole, not just a feature gap). |
| 8 | Agent Incident Response | Roadmap — containment primitives exist (resource kill, tool blocking); orchestration + severity tiers + playbooks to follow. |
| ★ | *Not in CrowdStrike* | Roadmap — signed **MCP Security Conformance Level**: scanner proof ↔ runtime enforcement ↔ audit chain as one verifiable artifact. A closed platform cannot offer vendor-independent conformance proof. |

The differentiator is the trust model: a closed SOC product asks you to believe its dashboard; mcp-armor's enforcement is in-process and its audit chain is independently verifiable.

## What It Is Not

- **Not a replacement for cosai-mcp.** The scanner detects protocol-level failures that require seeing the server's responses to adversarial inputs. mcp-armor cannot replicate that from inside.
- **Not a WAF.** mcp-armor operates at the MCP protocol layer, not the HTTP layer. It does not inspect TLS, headers unrelated to MCP, or raw TCP.
- **Not a complete penetration test substitute.** mcp-armor enforces the 12 CoSAI categories. Application-layer business logic, authentication backend security, and infrastructure hardening are out of scope.
- **Not opinionated about your auth stack.** The T1 `AuthEngine` validates the DPoP proof and token structure. It does not tell you which identity provider to use.
