# mcp-armor — Contributing

## Project Goals

mcp-armor is the server-side complement to the cosai-mcp scanner. Every contribution should move one of these metrics:

1. **Coverage** — more of the 40 CoSAI sub-threats implemented (not stubbed)
2. **Correctness** — existing engines made more accurate (fewer false positives/negatives)
3. **Adoption** — lower friction for server authors to integrate

## Development Setup

```bash
git clone https://github.com/cosai-oasis/mcp-armor
cd mcp-armor
pip install -e ".[dev]"
pytest
```

Required: Python 3.11+, `google-re2` (for production-faithful regex behaviour).

## Code Standards

**Immutability:** all public result types must be frozen dataclasses. Use `tuple` for list-valued fields, `MappingProxyType` for dict-valued fields. Return new context objects from engine hooks — never mutate.

**Fail closed:** engines raise `CoSAIException` subclasses on violation. No `pass`, no `logger.warning("..."); return ctx`. If a security check fails, the request must not proceed.

**RE2 for regex:** use `google-re2` for all pattern matching. Validate patterns at engine construction time. Stdlib `re` fallback is acceptable for development only.

**Escape at ingestion:** if you add code that reads from `MCPResponse`, use `resp.raw_body` (already escaped) — never re-read from a raw dict that hasn't been through `MCPResponse.from_dict()`.

**Tests are part of the deliverable:** every engine change needs a corresponding test. Every CoSAI sub-threat must have at least one test that demonstrates the engine blocking the attack. A PR without tests for new sub-threats is incomplete.

## Adding a New Engine or Sub-Threat

1. Identify the sub-threat ID (e.g., `T1-003`), category, and target layer (1, 2, or 3)
2. Find the existing engine file (`engines/auth.py` for T1) and add the logic there
3. Update `docs/COVERAGE.md` — move the sub-threat from "Not implemented" to "Done"
4. Add a test in `tests/engines/test_auth.py` named `test_t1_003_*`
5. If the sub-threat requires a new pattern, add it to the relevant patterns list in the engine file — not in `boundary.py` (which is T4-specific)

## Implementing a Stub Engine

Several engines are currently stubs (`SessionEngine`, full `ValidationEngine`, etc.). To implement:

1. Read the relevant section in `docs/THREAT_MAPPING.md` to understand the threat
2. Read the corresponding section in `docs/COVERAGE.md` to see what sub-threats need covering
3. Implement the lifecycle hook(s) that apply to this engine's layer
4. Ensure `on_startup()` raises `CoSAIException` for misconfiguration (startup-only engines T8, T11) or `pass` (all others)
5. Run the panel gate: T1 for auth/session/authz engines, T2 for all others

## Panel Gates (from global CLAUDE.md)

| Engine | Panel Tier | Reason |
|---|---|---|
| `AuthEngine` (T1) | T1 — Full + Adversary | New auth logic |
| `AuthzEngine` (T2) | T1 — Full + Adversary | New access control logic |
| `SessionEngine` (T7) | T1 — Full + Adversary | Session security |
| `BoundaryEngine` (T4) | T2 — Sonnet only | Content scanning, no auth path |
| `ValidationEngine` (T3) | T2 — Sonnet only | Input validation, no auth path |
| All others | T2 — Sonnet only | Non-auth feature work |
| Test-only changes | T3 — Skip | |

## PR Checklist

- [ ] All existing tests pass (`pytest`)
- [ ] Type check passes (`mypy --strict mcp_armor/`)
- [ ] Lint passes (`ruff check mcp_armor/ tests/`)
- [ ] `docs/COVERAGE.md` updated to reflect new sub-threat status
- [ ] Test added for each new sub-threat
- [ ] Panel gate run at appropriate tier (see table above)
- [ ] No `MagicMock` or bare `lambda` in test mocks — use `create_autospec`

## Commit Convention

```
feat(T4): complete definition scan at session open
fix(audit): resolve _write() race condition under concurrency
test(T3): add path traversal and SQL injection coverage
docs: update COVERAGE.md for T6-002 implementation
```

Prefix with `feat`, `fix`, `test`, or `docs`. Include the threat category in parentheses when relevant.
