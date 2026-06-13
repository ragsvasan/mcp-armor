"""Regression tests for the three-lens security audit (docs/AUDIT_2026-06-12.md).

Each test enters at a public entry point — guard.startup() / from_config() /
CoSAIGuard() construction — not at an engine helper, so it proves the fix on the
path an operator actually exercises.
"""

from __future__ import annotations

import pytest

from mcp_armor.config import ConfigError
from mcp_armor.engines.audit import AuditEngine
from mcp_armor.engines.session import SessionEngine
from mcp_armor.exceptions import AuditChainError, NetworkBindingError
from mcp_armor.guard import CoSAIGuard

from .conftest import make_ctx


def _write_yaml(tmp_path, body: str) -> str:
    p = tmp_path / "cosai.yaml"
    p.write_text(body)
    return str(p)


def _only(tmp_path, blocks: dict[str, str]) -> str:
    """Write a cosai.yaml enabling ONLY the named threat blocks (every other
    threat explicitly disabled). An absent block defaults to enabled=true, so
    isolation requires disabling the rest."""
    lines = ["version: 1", "threats:"]
    for i in range(1, 13):
        key = f"T{i}"
        if key in blocks:
            lines.append(f"  {key}:")
            lines.append("    enabled: true")
            for ln in blocks[key].splitlines():
                lines.append(f"    {ln}")
        else:
            lines.append(f"  {key}:")
            lines.append("    enabled: false")
    return _write_yaml(tmp_path, "\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# A2 — T7 DPoP binding was a no-op label; flag + YAML key removed.
# ---------------------------------------------------------------------------


def test_regression_a2_bind_session_to_dpop_key_now_rejected(tmp_path) -> None:
    """The removed T7 `bind_session_to_dpop` key must be rejected as unknown —
    proving the no-op label is gone from the config surface."""
    cfg = _write_yaml(
        tmp_path,
        "version: 1\nthreats:\n  T7:\n    enabled: true\n    bind_session_to_dpop: true\n",
    )
    with pytest.raises(ConfigError, match="bind_session_to_dpop"):
        CoSAIGuard.from_config(cfg)


def test_regression_a2_session_engine_has_no_dpop_binding_attr() -> None:
    """SessionEngine must no longer carry the dead `_bind_to_dpop` attribute."""
    eng = SessionEngine()
    assert not hasattr(eng, "_bind_to_dpop")


# ---------------------------------------------------------------------------
# A3 — T8 startup bind check is now wired from config.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_a3_bind_host_0000_raises_at_startup(tmp_path) -> None:
    """A config with T8 bind_host: 0.0.0.0 and allow_public_bind: false must
    raise NetworkBindingError at guard.startup() (previously dead — no bind_host
    field existed on T8Config)."""
    cfg = _only(
        tmp_path,
        {"T8": "allow_public_bind: false\nbind_host: 0.0.0.0\nbind_port: 8000"},
    )
    guard = CoSAIGuard.from_config(cfg)
    with pytest.raises(NetworkBindingError, match="0.0.0.0"):  # noqa: S104
        await guard.startup()


@pytest.mark.asyncio
async def test_regression_a3_loopback_bind_host_starts_cleanly(tmp_path) -> None:
    """A loopback bind_host must NOT raise at startup."""
    cfg = _only(tmp_path, {"T8": "bind_host: 127.0.0.1\nbind_port: 8000"})
    guard = CoSAIGuard.from_config(cfg)
    await guard.startup()  # must not raise


# ---------------------------------------------------------------------------
# A4 — T12 rollback-to-empty bypass.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_a4_deleting_log_keeping_sidecar_raises(tmp_path) -> None:
    """Write N records (creates the log + .hwm sidecar), delete only the log,
    then a fresh guard.startup() must raise AuditChainError — not silently
    re-seed an empty chain (full-history erasure must be detectable)."""
    log_path = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log_path, verify_on_startup=True)
    guard = CoSAIGuard([engine])
    await guard.startup()
    ctx = make_ctx()
    for _ in range(3):
        await engine._append("request", ctx, "tools/call", "digest")

    assert log_path.exists()
    sidecar = tmp_path / "audit.jsonl.hwm"
    assert sidecar.exists(), "expected HWM sidecar to exist after writes"

    # Attacker deletes the log but the tamper-evident sidecar survives.
    log_path.unlink()

    fresh = AuditEngine(path=log_path, verify_on_startup=True)
    fresh_guard = CoSAIGuard([fresh])
    with pytest.raises(AuditChainError, match="rolled back|absent"):
        await fresh_guard.startup()


# ---------------------------------------------------------------------------
# A6 — ARMOR_AUDIT_HMAC_KEY mandatory when T12 enabled (outside dev profile).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_a6_t12_without_hmac_key_refuses_startup(tmp_path, monkeypatch) -> None:
    """from_config with T12 enabled and no ARMOR_AUDIT_HMAC_KEY must raise at
    guard.startup() — an unsigned chain is forgeable."""
    monkeypatch.delenv("ARMOR_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("ARMOR_AUDIT_ALLOW_UNSIGNED", raising=False)
    log_path = tmp_path / "audit.jsonl"
    cfg = _only(tmp_path, {"T12": f"path: {log_path}"})
    guard = CoSAIGuard.from_config(cfg)
    with pytest.raises(AuditChainError, match="ARMOR_AUDIT_HMAC_KEY"):
        await guard.startup()


@pytest.mark.asyncio
async def test_regression_a6_dev_escape_allows_unsigned_startup(tmp_path, monkeypatch) -> None:
    """The documented dev escape (ARMOR_AUDIT_ALLOW_UNSIGNED=1) lets an unsigned
    T12 chain start."""
    monkeypatch.delenv("ARMOR_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.setenv("ARMOR_AUDIT_ALLOW_UNSIGNED", "1")
    log_path = tmp_path / "audit.jsonl"
    cfg = _only(tmp_path, {"T12": f"path: {log_path}"})
    guard = CoSAIGuard.from_config(cfg)
    await guard.startup()  # must not raise


@pytest.mark.asyncio
async def test_regression_a6_require_hmac_key_false_allows_unsigned(tmp_path, monkeypatch) -> None:
    """T12.require_hmac_key: false (dev profile) accepts an unsigned chain."""
    monkeypatch.delenv("ARMOR_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("ARMOR_AUDIT_ALLOW_UNSIGNED", raising=False)
    log_path = tmp_path / "audit.jsonl"
    cfg = _only(tmp_path, {"T12": f"path: {log_path}\nrequire_hmac_key: false"})
    guard = CoSAIGuard.from_config(cfg)
    await guard.startup()  # must not raise


# ---------------------------------------------------------------------------
# B6 — dry_run hard prod guard.
# ---------------------------------------------------------------------------


def test_regression_b6_dry_run_refused_without_ack(monkeypatch) -> None:
    """CoSAIGuard(dry_run=True) must be refused unless ARMOR_ALLOW_DRY_RUN=1."""
    monkeypatch.delenv("ARMOR_ALLOW_DRY_RUN", raising=False)
    with pytest.raises(RuntimeError, match="ARMOR_ALLOW_DRY_RUN"):
        CoSAIGuard([SessionEngine()], dry_run=True)


def test_regression_b6_dry_run_allowed_with_ack(monkeypatch) -> None:
    """With the env acknowledgement, dry_run construction succeeds."""
    monkeypatch.setenv("ARMOR_ALLOW_DRY_RUN", "1")
    guard = CoSAIGuard([SessionEngine()], dry_run=True)
    assert guard._dry_run is True


# ===========================================================================
# Post-panel hardening regression tests (panel findings R1–R4)
# ===========================================================================


# R1 — A1 schema store: no self-DoS without a manifest; no downgrade by a later manifest.


@pytest.mark.asyncio
async def test_regression_a1_no_self_dos_without_manifest() -> None:
    """strict_schema must NOT hard-reject a tools/call when no tools/list manifest
    has been observed on this engine instance (dispatcher/fastmcp/multi-worker
    paths) — that was the very self-DoS A1 set out to fix."""
    from types import MappingProxyType

    from mcp_armor.engines.validation import ValidationEngine
    from mcp_armor.types import MCPRequest

    eng = ValidationEngine(strict_schema=True)  # no manifest registered
    req = MCPRequest(
        method="tools/call",
        params=MappingProxyType({"name": "echo", "arguments": {"message": "hello"}}),
        session_id="s",
        raw_headers=MappingProxyType({}),
        transport="stdio",
    )
    # Must not raise "no registered schema" — schema gate is skipped pre-manifest.
    await eng.on_request(make_ctx(), req)


@pytest.mark.asyncio
async def test_regression_a1_schema_not_overwritten_by_later_manifest() -> None:
    """A later/poisoned tools/list must not relax an already-registered strict
    schema (first-write-wins; shared process-global store)."""
    from types import MappingProxyType

    from mcp_armor.engines.validation import ValidationEngine
    from mcp_armor.exceptions import ValidationError
    from mcp_armor.types import MCPRequest, MCPResponse

    eng = ValidationEngine(strict_schema=True)
    strict = {
        "name": "echo",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        },
    }
    await eng.on_response(
        make_ctx(),
        MCPResponse(result=MappingProxyType({"tools": [strict]}), error=None, raw_body=""),
    )
    # Attacker/drift sends a permissive empty schema for the same tool.
    loose = {"name": "echo", "inputSchema": {}}
    await eng.on_response(
        make_ctx(),
        MCPResponse(result=MappingProxyType({"tools": [loose]}), error=None, raw_body=""),
    )

    # The strict schema must still be enforced — message:123 violates type:string.
    bad = MCPRequest(
        method="tools/call",
        params=MappingProxyType({"name": "echo", "arguments": {"message": 123}}),
        session_id="s",
        raw_headers=MappingProxyType({}),
        transport="http",
    )
    with pytest.raises(ValidationError):
        await eng.on_request(make_ctx(), bad)


# R2 — A3 wildcard bind check covers IPv6 spellings.


def test_regression_a3_wildcard_ipv6_spellings_raise() -> None:
    """check_bind_address must reject every unspecified-address spelling, not just
    the two literals '0.0.0.0' / '::'."""
    from mcp_armor.engines.network import NetworkEngine

    eng = NetworkEngine(allow_public_bind=False)
    wildcards = ("0.0.0.0", "::", "[::]", "::0", "0:0:0:0:0:0:0:0", "0", "::ffff:0.0.0.0")  # noqa: S104
    for host in wildcards:
        with pytest.raises(NetworkBindingError):
            eng.check_bind_address(host, 8000)
    # explicit interface must NOT raise
    eng.check_bind_address("127.0.0.1", 8000)
    eng.check_bind_address("10.1.2.3", 8000)


# R3 — audit HMAC key minimum length.


def test_regression_audit_hmac_key_too_short_rejected(tmp_path, monkeypatch) -> None:
    """A sub-32-byte ARMOR_AUDIT_HMAC_KEY must be rejected at construction."""
    from mcp_armor.config import ConfigError

    monkeypatch.setenv("ARMOR_AUDIT_HMAC_KEY", "00" * 16)  # 16 bytes < 32
    with pytest.raises(ConfigError, match="too short"):
        AuditEngine(path=tmp_path / "audit.jsonl")


# R4 — audit startup TOCTOU: log vanishing during verify surfaces as AuditChainError.


@pytest.mark.asyncio
async def test_regression_a4_log_vanishes_during_verify_raises_chain_error(
    tmp_path, monkeypatch
) -> None:
    """If the log is deleted between the existence check and verification, startup
    must raise AuditChainError, not a bare FileNotFoundError."""
    log_path = tmp_path / "audit.jsonl"
    log_path.write_text("")  # exists at check time
    engine = AuditEngine(path=log_path, verify_on_startup=True)

    async def _boom() -> None:
        raise FileNotFoundError(str(log_path))

    monkeypatch.setattr(engine, "_verify_chain_async", _boom)
    with pytest.raises(AuditChainError, match="vanished|concurrent deletion"):
        await engine.on_startup()
