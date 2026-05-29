"""Tests for AuditEngine — hash-chain correctness and race-condition fix."""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

import pytest

from mcp_armor.engines.audit import AuditEngine, _canonical
from tests.conftest import make_ctx


def _read_entries(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Race-condition regression (Bug #1)
# ---------------------------------------------------------------------------


def test_regression_race_condition_prev_hash(tmp_path):
    """prev_hash in each record must equal the previous entry's chain_hash."""
    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    ctx = make_ctx()

    for _ in range(5):
        engine._write_sync("request", ctx, "tools/call", "digest")

    entries = _read_entries(log)
    assert len(entries) == 5
    genesis = "0" * 64
    for i, entry in enumerate(entries):
        expected_prev = genesis if i == 0 else entries[i - 1]["chain_hash"]
        assert entry["prev_hash"] == expected_prev, (
            f"Entry {i}: prev_hash={entry['prev_hash']!r} expected={expected_prev!r}"
        )


def test_regression_race_condition_concurrent_writes(tmp_path):
    """Concurrent writes must produce a valid, non-corrupted hash chain."""
    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    ctx = make_ctx()

    errors: list[Exception] = []

    def writer():
        try:
            for _ in range(10):
                engine._write_sync("request", ctx, "tools/call", "d")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Writer threads raised: {errors}"

    entries = _read_entries(log)
    assert len(entries) == 50

    # Verify every link using the canonical hash formula
    for i, entry in enumerate(entries):
        expected = hashlib.sha256(_canonical(entry)).hexdigest()
        assert entry["chain_hash"] == expected, f"Chain broken at entry {i}"
        assert entry["prev_hash"] == ("0" * 64 if i == 0 else entries[i - 1]["chain_hash"]), (
            f"Wrong prev_hash at entry {i}"
        )


# ---------------------------------------------------------------------------
# Chain-hash covers the full record body (FIX [3])
# ---------------------------------------------------------------------------


def test_regression_chain_hash_covers_full_record(tmp_path):
    """chain_hash = sha256(canonical JSON of all auditable fields)."""
    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    ctx = make_ctx()

    engine._write_sync("session_start", ctx, "", "")
    entries = _read_entries(log)
    e = entries[0]

    expected = hashlib.sha256(_canonical(e)).hexdigest()
    assert e["chain_hash"] == expected

    # Old formula (prev_hash + entry_id only) must NOT match — confirms the fix
    old_formula = hashlib.sha256(f"{'0' * 64}{e['entry_id']}".encode()).hexdigest()
    assert e["chain_hash"] != old_formula, (
        "chain_hash still uses old entry_id-only formula — body tampering is undetectable"
    )


def test_regression_body_tampering_detected(tmp_path):
    """
    Tampering any auditable field (e.g. user_id) must break the chain.
    Before FIX[3], only chain_hash tampering was detected.
    """
    from mcp_armor.exceptions import AuditChainError

    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    ctx = make_ctx()

    engine._write_sync("request", ctx, "tools/call", "d")
    engine._write_sync("request", ctx, "tools/call", "d")

    lines = log.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["user_id"] = "attacker"  # tamper body field, leave chain_hash intact
    lines[0] = json.dumps(entry)
    log.write_text("\n".join(lines) + "\n")

    with pytest.raises(AuditChainError, match="chain broken|Audit chain"):
        engine._verify_chain()


# ---------------------------------------------------------------------------
# _verify_chain
# ---------------------------------------------------------------------------


def test_verify_chain_passes_on_valid_log(tmp_path):
    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    ctx = make_ctx()

    for _ in range(3):
        engine._write_sync("request", ctx, "tools/call", "d")

    engine._verify_chain()  # must not raise


def test_verify_chain_detects_chain_hash_tamper(tmp_path):
    from mcp_armor.exceptions import AuditChainError

    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    ctx = make_ctx()

    engine._write_sync("request", ctx, "tools/call", "d")
    engine._write_sync("request", ctx, "tools/call", "d")

    lines = log.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["chain_hash"] = "0" * 64
    lines[0] = json.dumps(entry)
    log.write_text("\n".join(lines) + "\n")

    with pytest.raises(AuditChainError, match="chain broken|Audit chain"):
        engine._verify_chain()


def test_regression_verify_chain_updates_prev_hash_under_lock(tmp_path):
    """_verify_chain must update self._prev_hash under self._lock."""
    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    ctx = make_ctx()

    engine._write_sync("request", ctx, "tools/call", "d")
    entries = _read_entries(log)
    last_hash = entries[-1]["chain_hash"]

    engine._verify_chain()

    # After _verify_chain, self._prev_hash must equal the last entry's chain_hash
    assert engine._prev_hash == last_hash


# ---------------------------------------------------------------------------
# on_* hooks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_request_returns_ctx_with_audit_parent(tmp_path):
    from types import MappingProxyType

    from mcp_armor.types import MCPRequest

    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    ctx = make_ctx()

    req = MCPRequest(
        method="tools/call",
        params=MappingProxyType({"name": "search", "arguments": {}}),
        session_id=ctx.session_id,
        raw_headers=MappingProxyType({}),
    )
    new_ctx = await engine.on_request(ctx, req)
    assert new_ctx.audit_parent_id is not None
    assert new_ctx.audit_parent_id != ctx.audit_parent_id


@pytest.mark.asyncio
async def test_on_startup_creates_log_dir(tmp_path):
    log = tmp_path / "deep" / "nested" / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    await engine.on_startup()
    assert log.parent.exists()


# ---------------------------------------------------------------------------
# Fix 1 — Async I/O does not block the event loop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_write_does_not_block_event_loop(tmp_path):
    """
    50 concurrent on_request calls must all complete within 2 seconds.
    If file I/O blocked the event loop, tasks would serialize and take much longer.
    """
    import asyncio as _asyncio
    from types import MappingProxyType

    from mcp_armor.types import MCPRequest

    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    await engine.on_startup()
    ctx = make_ctx()

    async def one_call(i: int) -> None:
        req = MCPRequest(
            method="tools/call",
            params=MappingProxyType({"name": f"tool_{i}", "arguments": {}}),
            session_id=ctx.session_id,
            raw_headers=MappingProxyType({}),
        )
        await engine.on_request(ctx, req)

    import time

    start = time.monotonic()
    await _asyncio.gather(*[one_call(i) for i in range(50)])
    elapsed = time.monotonic() - start

    entries = _read_entries(log)
    assert len(entries) == 50
    assert elapsed < 2.0, f"50 concurrent audit writes took {elapsed:.2f}s — likely blocking"


# ---------------------------------------------------------------------------
# Fix 4 — HMAC signing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_hmac_present_when_key_set(tmp_path, monkeypatch):
    """chain_hmac must be present and verifiable when ARMOR_AUDIT_HMAC_KEY is set."""
    import hmac as _hmac_mod

    key_hex = "aa" * 32
    monkeypatch.setenv("ARMOR_AUDIT_HMAC_KEY", key_hex)

    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    await engine.on_startup()

    from types import MappingProxyType

    from mcp_armor.engines.audit import _canonical, _compute_chain_hmac
    from mcp_armor.types import MCPRequest

    ctx = make_ctx()
    req = MCPRequest(
        method="tools/call",
        params=MappingProxyType({"name": "test_tool", "arguments": {}}),
        session_id=ctx.session_id,
        raw_headers=MappingProxyType({}),
    )
    await engine.on_request(ctx, req)

    entries = _read_entries(log)
    assert len(entries) == 1
    entry = entries[0]
    assert "chain_hmac" in entry, "chain_hmac must be present when key is set"

    # Verify HMAC is correct
    key = bytes.fromhex(key_hex)
    expected_hmac = _compute_chain_hmac(key, _canonical(entry))
    assert _hmac_mod.compare_digest(entry["chain_hmac"], expected_hmac)


@pytest.mark.asyncio
async def test_audit_chain_tamper_detected_with_hmac(tmp_path, monkeypatch):
    """Truncating the log and recalculating hashes without HMAC key must be detected."""
    from mcp_armor.exceptions import AuditChainError

    key_hex = "bb" * 32
    monkeypatch.setenv("ARMOR_AUDIT_HMAC_KEY", key_hex)

    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    await engine.on_startup()
    ctx = make_ctx()

    # Write 3 records
    from types import MappingProxyType

    from mcp_armor.types import MCPRequest

    for i in range(3):
        req = MCPRequest(
            method="tools/call",
            params=MappingProxyType({"name": f"tool_{i}", "arguments": {}}),
            session_id=ctx.session_id,
            raw_headers=MappingProxyType({}),
        )
        await engine.on_request(ctx, req)

    entries = _read_entries(log)
    assert len(entries) == 3

    # Attacker truncates to 1 record and recalculates chain_hash WITHOUT the HMAC key.
    # The chain_hmac on record 0 was signed with the real key — removing it and
    # re-writing chain_hash would fail HMAC verification; we simulate dropping chain_hmac.
    first = entries[0].copy()
    first.pop("chain_hmac", None)  # simulate attacker who doesn't have the key
    # Recalculate chain_hash for the tampered record
    first["chain_hash"] = hashlib.sha256(_canonical(first)).hexdigest()
    log.write_text(json.dumps(first) + "\n")
    # Reset the HWM sidecar to match the truncated log so hwm check doesn't fire first
    hwm_path = Path(str(log) + ".hwm")
    hwm_path.write_text(json.dumps({"count": 1, "head": first["chain_hash"]}))

    # A fresh engine with the HMAC key must detect the missing chain_hmac
    engine2 = AuditEngine(path=log, verify_on_startup=False)
    with pytest.raises(AuditChainError, match="chain_hmac|HMAC"):
        await engine2._verify_chain_async()


# ---------------------------------------------------------------------------
# Fix 1 — concurrent _append must not reorder records
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_concurrent_append_no_chain_break(tmp_path, monkeypatch):
    """30 concurrent _append calls must produce a valid chain (no sequence gaps)."""
    import asyncio as _asyncio
    from types import MappingProxyType

    from mcp_armor.exceptions import AuditChainError
    from mcp_armor.types import MCPRequest

    monkeypatch.delenv("ARMOR_AUDIT_HMAC_KEY", raising=False)
    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    await engine.on_startup()

    ctx = make_ctx()
    reqs = [
        MCPRequest(
            method="tools/call",
            params=MappingProxyType({"name": f"tool_{i}", "arguments": {}}),
            session_id=ctx.session_id,
            raw_headers=MappingProxyType({}),
        )
        for i in range(30)
    ]
    # Fire 30 concurrent appends.
    await _asyncio.gather(
        *(engine._append("request", ctx, req.method, str(i)) for i, req in enumerate(reqs))
    )

    # Chain verification must pass — no gaps, no hash mismatches.
    try:
        await engine._verify_chain_async()
    except AuditChainError as exc:
        pytest.fail(f"Concurrent appends broke the audit chain: {exc}")

    entries = _read_entries(log)
    assert len(entries) == 30, "All 30 records must be present"
    # Sequence numbers must be a consecutive permutation of 0-29.
    seqs = sorted(e["seq"] for e in entries)
    assert seqs == list(range(30)), f"Sequence numbers not consecutive: {seqs}"


# ---------------------------------------------------------------------------
# Fix 6 — malformed HMAC key must fail at startup, not mid-request
# ---------------------------------------------------------------------------


def test_regression_malformed_hmac_key_fails_at_startup(tmp_path, monkeypatch):
    """A non-hex ARMOR_AUDIT_HMAC_KEY must raise ConfigError during AuditEngine init."""
    from mcp_armor.config import ConfigError

    monkeypatch.setenv("ARMOR_AUDIT_HMAC_KEY", "not-valid-hex!!!!")
    with pytest.raises(ConfigError, match="hex"):
        AuditEngine(path=tmp_path / "audit.jsonl", verify_on_startup=False)


# ---------------------------------------------------------------------------
# Fix 7 — HMAC key rotation: old-key records verified with prev key, no crash
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regression_hmac_key_rotation_no_startup_crash(tmp_path, monkeypatch):
    """After key rotation, _verify_chain_async must pass (using prev key) with a warning."""
    from types import MappingProxyType

    from mcp_armor.types import MCPRequest

    old_key_hex = "cc" * 32
    new_key_hex = "dd" * 32

    monkeypatch.setenv("ARMOR_AUDIT_HMAC_KEY", old_key_hex)
    monkeypatch.delenv("ARMOR_AUDIT_HMAC_KEY_PREV", raising=False)

    log_path = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log_path, verify_on_startup=False)
    await engine.on_startup()

    ctx = make_ctx()
    for i in range(3):
        req = MCPRequest(
            method="tools/call",
            params=MappingProxyType({"name": f"tool_{i}", "arguments": {}}),
            session_id=ctx.session_id,
            raw_headers=MappingProxyType({}),
        )
        await engine.on_request(ctx, req)

    # Rotate: new key active, old key in prev.
    monkeypatch.setenv("ARMOR_AUDIT_HMAC_KEY", new_key_hex)
    monkeypatch.setenv("ARMOR_AUDIT_HMAC_KEY_PREV", old_key_hex)

    engine2 = AuditEngine(path=log_path, verify_on_startup=False)
    # Should NOT raise even though records were signed with old_key.
    # The rotation warning goes through logging, not warnings.warn — just verify no exception.
    try:
        await engine2._verify_chain_async()
    except Exception as exc:
        pytest.fail(f"Key rotation caused unexpected startup crash: {exc}")


# ---------------------------------------------------------------------------
# Fix 11 — HMAC sticky marker prevents silent downgrade
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exploit_hmac_downgrade_rejected_by_marker(tmp_path, monkeypatch):
    """After HMAC was enabled (marker exists), removing the key must raise AuditChainError."""
    from types import MappingProxyType

    from mcp_armor.exceptions import AuditChainError
    from mcp_armor.types import MCPRequest

    key_hex = "ee" * 32
    monkeypatch.setenv("ARMOR_AUDIT_HMAC_KEY", key_hex)

    log_path = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log_path, verify_on_startup=False)
    await engine.on_startup()  # creates .hmac_enabled marker

    ctx = make_ctx()
    req = MCPRequest(
        method="tools/call",
        params=MappingProxyType({"name": "tool", "arguments": {}}),
        session_id=ctx.session_id,
        raw_headers=MappingProxyType({}),
    )
    await engine.on_request(ctx, req)

    # Marker file must exist.
    marker = tmp_path / "audit.jsonl.hmac_enabled"
    assert marker.exists(), "HMAC marker file must be created on first startup with key"

    # Remove the key — simulate attacker stripping the env var.
    monkeypatch.delenv("ARMOR_AUDIT_HMAC_KEY")
    monkeypatch.delenv("ARMOR_AUDIT_HMAC_KEY_PREV", raising=False)

    engine2 = AuditEngine(path=log_path, verify_on_startup=False)
    with pytest.raises(AuditChainError, match="HMAC was previously enabled"):
        await engine2._verify_chain_async()
