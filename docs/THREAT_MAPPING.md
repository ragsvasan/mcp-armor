# mcp-armor — Threat Mapping

CoSAI T1–T12 mapped to OWASP MCP Top 10, ISO 27001:2022, NIST AI RMF 2.0, and CWE.

| CoSAI | Name | Engine | OWASP MCP | ISO 27001:2022 | NIST AI RMF | CWE |
|-------|------|--------|-----------|----------------|-------------|-----|
| T1 | Improper Authentication | `AuthEngine` | MCP-Top10-A01 | A.9.4.2, A.9.4.3 | GV-OV.OA.2, MG-MT.2 | CWE-287, CWE-306 |
| T2 | Missing Access Control | `AuthzEngine` | MCP-Top10-A02 | A.9.4.1, A.18.1.3 | GV-OV.PO.5, MP-MT.2 | CWE-285, CWE-732 |
| T3 | Input Validation Failures | `ValidationEngine` | MCP-Top10-A03 | A.14.2.5, A.8.28 | MG-MR.2, MG-MT.1 | CWE-78, CWE-22, CWE-89 |
| T4 | Data/Control Boundary | `BoundaryEngine` | MCP-Top10-A04 | A.14.2.5, A.8.28 | MG-MR.3, MG-AI.2 | CWE-74, CWE-77 |
| T5 | Inadequate Data Protection | `ProtectionEngine` | MCP-Top10-A05 | A.8.12, A.8.11 | MP-ID.1, MG-MT.3 | CWE-200, CWE-312 |
| T6 | Integrity/Verification | `IntegrityEngine` | MCP-Top10-A06 | A.8.8, A.15.2.1 | GV-OV.SC.2, MG-MT.4 | CWE-345, CWE-494 |
| T7 | Session Security Failures | `SessionEngine` | MCP-Top10-A07 | A.9.4.2, A.9.4.3 | MG-MT.2, GV-OV.OA.2 | CWE-384, CWE-287 |
| T8 | Network Binding Failures | `NetworkEngine` | MCP-Top10-A08 | A.13.1.3, A.8.20 | GV-OV.OA.1, MP-ID.2 | CWE-668, CWE-441 |
| T9 | Trust Boundary Failures | `TrustEngine` | MCP-Top10-A09 | A.14.2.5, A.8.28 | MG-AI.3, MG-MR.4 | CWE-602, CWE-807 |
| T10 | Resource Management | `ResourceEngine` | MCP-Top10-A10 | A.12.1.3, A.17.2.1 | GV-OV.OA.3, MP-OV.3 | CWE-400, CWE-770 |
| T11 | Supply Chain/Lifecycle | `SupplyChainEngine` | — | A.15.1.1, A.15.2.1 | GV-OV.SC.1, GV-OV.SC.3 | CWE-494, CWE-1357 |
| T12 | Insufficient Logging | `AuditEngine` | — | A.12.4.1, A.12.4.3 | MG-MT.5, GV-OV.OA.5 | CWE-778, CWE-223 |

---

## Detailed Threat Descriptions

### T1 — Improper Authentication

**Core risk:** An attacker impersonates a legitimate user or agent by forging, replaying, or stealing authentication credentials.

**Sub-threats covered by `AuthEngine`:**
- T1-001: No `Authorization` header — server accepts unauthenticated requests
- T1-002: Token replay — used `jti` accepted a second time
- T1-003: Cross-session token — token issued for session A used in session B
- T1-004: DPoP binding failure — bearer token without required proof-of-possession

**ISO 27001 controls:** A.9.4.2 (secure log-on procedures), A.9.4.3 (password management system)  
**NIST AI RMF:** GV-OV.OA-2 (AI risk governance), MG-MT-2 (monitoring)  
**CWE:** CWE-287 (improper authentication), CWE-306 (missing authentication for critical function)

---

### T2 — Missing Access Control

**Core risk:** A caller performs actions beyond their authorisation level. The classic MCP form is the "confused deputy" — an agent acting on user intent but using server-level credentials.

**Sub-threats covered by `AuthzEngine`:**
- T2-001: Confused deputy — service-account token executes user-requested privileged operation
- T2-002: No per-tool RBAC — all authenticated callers can invoke all tools
- T2-003: Multi-tenant data bleed — tenant A's session can access tenant B's data

**ISO 27001 controls:** A.9.4.1 (information access restriction), A.18.1.3 (protection of records)  
**NIST AI RMF:** GV-OV.PO-5 (policies and procedures), MP-MT-2 (monitoring)  
**CWE:** CWE-285 (improper authorization), CWE-732 (incorrect permission assignment)

---

### T3 — Input Validation Failures

**Core risk:** Attacker-controlled strings in tool arguments reach downstream systems (shell, database, filesystem) without sanitisation.

**Sub-threats covered by `ValidationEngine`:**
- T3-001: Oversized payload — exhausts memory or triggers O(n²) processing
- T3-002: Command injection — `; rm -rf /` in a string argument
- T3-003: Path traversal — `../../etc/passwd` in a file path argument
- T3-004: SQL injection — unparameterised query construction from tool input
- T3-005: Schema violation — unknown fields accepted when strict mode is off

**ISO 27001 controls:** A.14.2.5 (secure system engineering), A.8.28 (secure coding)  
**NIST AI RMF:** MG-MR-2 (risk response), MG-MT-1 (monitoring)  
**CWE:** CWE-78 (OS command injection), CWE-22 (path traversal), CWE-89 (SQL injection)

---

### T4 — Data/Control Boundary

**Core risk:** An attacker embeds LLM instructions in data that flows into the agent's context, hijacking the agent's behaviour without touching the application layer.

**Sub-threats covered by `BoundaryEngine`:**
- T4-001: Tool definition poisoning — injection in `description`, `name`, or `inputSchema` properties
- T4-002: Indirect prompt injection — injection in tool call response bodies

**Why black-box cannot detect T4:** a scanner cannot observe what content flows into the LLM's reasoning context. Only middleware in the call path can see this.

**ISO 27001 controls:** A.14.2.5, A.8.28  
**NIST AI RMF:** MG-MR-3 (risk response), MG-AI-2 (AI-specific controls)  
**CWE:** CWE-74 (injection), CWE-77 (command injection through agent delegation)

---

### T5 — Inadequate Data Protection

**Core risk:** Personally identifiable information or secrets leak from tool responses into agent context or client output.

**Sub-threats covered by `ProtectionEngine`:**
- T5-001: PII in response (SSN, credit card, email, phone)
- T5-002: Secrets in response (JWT, API key, OAuth token)
- T5-003: Foreign session context — another user's data appears in this session's response

**ISO 27001 controls:** A.8.12 (data leakage prevention), A.8.11 (data masking)  
**NIST AI RMF:** MP-ID-1 (impact assessment), MG-MT-3 (monitoring)  
**CWE:** CWE-200 (exposure of sensitive information), CWE-312 (cleartext storage of sensitive information)

---

### T6 — Integrity/Verification

**Core risk:** Tool definitions are mutated mid-session or replaced by lookalike tools, changing the agent's behaviour without the caller's knowledge.

**Sub-threats covered by `IntegrityEngine`:**
- T6-001: Mid-session tool mutation ("rug pull") — tools/list changes between session open and probe
- T6-002: Typosquatting — tool name within edit distance 2 of an allowlist entry
- T6-003: Tool shadowing — two tools with names differing only in Unicode lookalikes

**ISO 27001 controls:** A.8.8 (management of technical vulnerabilities), A.15.2.1 (monitoring and review of supplier services)  
**NIST AI RMF:** GV-OV.SC-2 (supply chain), MG-MT-4 (monitoring)  
**CWE:** CWE-345 (insufficient verification of data authenticity), CWE-494 (download of code without integrity check)

---

### T7 — Session Security Failures

**Core risk:** An attacker hijacks or fixates a session, or replays a legitimate session token across a different transport.

**Sub-threats covered by `SessionEngine`:**
- T7-001: Session fixation — attacker pre-sets session ID, victim authenticates into it
- T7-002: Session ID in URL — leaks via Referer header or access logs
- T7-003: Cross-transport replay — stdio session token reused over HTTP
- T7-004: Context bleed — previous session's state carried into new session

**ISO 27001 controls:** A.9.4.2, A.9.4.3  
**NIST AI RMF:** MG-MT-2, GV-OV.OA-2  
**CWE:** CWE-384 (session fixation), CWE-287 (improper authentication)

---

### T8 — Network Binding Failures

**Core risk:** Server exposes itself beyond its intended network boundary, or tool arguments are used to trigger requests to internal infrastructure.

**Sub-threats covered by `NetworkEngine`:**
- T8-001: Server bound to 0.0.0.0 — accessible to all local network interfaces
- T8-002: SSRF via tool arguments — tool reaches AWS IMDS, internal APIs, or localhost services
- T8-003: Shadow MCP server — second MCP server running on same host, reachable from agent

**ISO 27001 controls:** A.13.1.3 (segregation in networks), A.8.20 (network security)  
**NIST AI RMF:** GV-OV.OA-1, MP-ID-2  
**CWE:** CWE-668 (exposure of resource to wrong sphere), CWE-441 (unintended proxy or intermediary)

---

### T9 — Trust Boundary Failures

**Core risk:** The system treats LLM-generated output as trustworthy input — feeding it back into tool arguments, shell commands, or further LLM prompts without sanitisation.

**Sub-threats covered by `TrustEngine`:**
- T9-001: Unsanitized LLM output used as tool argument (prompt injection propagation)
- T9-002: LLM-generated shell command or URL executed directly
- T9-003: Security decision delegated to LLM judgment (jailbreakable gate)

**ISO 27001 controls:** A.14.2.5, A.8.28  
**NIST AI RMF:** MG-AI-3 (AI-specific controls), MG-MR-4 (risk response)  
**CWE:** CWE-602 (client-side enforcement of server-side security), CWE-807 (reliance on untrusted inputs)

---

### T10 — Resource Management

**Core risk:** An agent, adversarial input, or runaway tool call exhausts computational resources or incurs unbounded cost.

**Sub-threats covered by `ResourceEngine`:**
- T10-001: Unbounded call count — denial of wallet via rapid tool calls
- T10-002: Wall-clock limit — session runs indefinitely
- T10-003: Recursive tool call loop — tool A calls tool B which calls tool A
- T10-004: Missing heartbeat — zombie session holds resources without progress

**ISO 27001 controls:** A.12.1.3 (capacity management), A.17.2.1 (availability of information processing facilities)  
**NIST AI RMF:** GV-OV.OA-3, MP-OV-3  
**CWE:** CWE-400 (uncontrolled resource consumption), CWE-770 (allocation of resources without limits)

---

### T11 — Supply Chain/Lifecycle

**Core risk:** A malicious tool is loaded into the server via a typosquatted name, unsigned package, or dependency confusion attack.

**Sub-threats covered by `SupplyChainEngine`:**
- T11-001: Unlisted tool loaded — tool not on the allowlist is registered
- T11-002: Typosquatted tool name — `search-db` vs `search_db` vs `searchdb`
- T11-003: Unsigned tool from untrusted registry
- T11-004: Dependency confusion — internal package name shadowed by public registry entry

**ISO 27001 controls:** A.15.1.1 (information security policy for supplier relationships), A.15.2.1  
**NIST AI RMF:** GV-OV.SC-1, GV-OV.SC-3 (supply chain risk management)  
**CWE:** CWE-494 (download of code without integrity check), CWE-1357 (reliance on insufficiently trustworthy component)

---

### T12 — Insufficient Logging

**Core risk:** Agent actions are not recorded or are recorded in a tamper-able form, making incident reconstruction impossible.

**Sub-threats covered by `AuditEngine`:**
- T12-001: No execution trace — cannot reconstruct what the agent did
- T12-002: Log tampering — audit trail modified after the fact
- T12-003: PII in logs — raw tool parameters stored (privacy violation)
- T12-004: Missing DAG parent — concurrent calls cannot be ordered in the audit timeline

**ISO 27001 controls:** A.12.4.1 (event logging), A.12.4.3 (administrator and operator logs)  
**NIST AI RMF:** MG-MT-5 (monitoring), GV-OV.OA-5 (accountability)  
**CWE:** CWE-778 (insufficient logging), CWE-223 (omission of security-relevant information)
