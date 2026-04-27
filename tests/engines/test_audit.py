"""Tests for AuditEngine — hash-chain correctness and race-condition fix."""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
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
        engine._write("request", ctx, "tools/call", "digest")

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
                engine._write("request", ctx, "tools/call", "d")
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
        assert entry["prev_hash"] == (
            "0" * 64 if i == 0 else entries[i - 1]["chain_hash"]
        ), f"Wrong prev_hash at entry {i}"


# ---------------------------------------------------------------------------
# Chain-hash covers the full record body (FIX [3])
# ---------------------------------------------------------------------------

def test_regression_chain_hash_covers_full_record(tmp_path):
    """chain_hash = sha256(canonical JSON of all auditable fields)."""
    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    ctx = make_ctx()

    engine._write("session_start", ctx, "", "")
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

    engine._write("request", ctx, "tools/call", "d")
    engine._write("request", ctx, "tools/call", "d")

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
        engine._write("request", ctx, "tools/call", "d")

    engine._verify_chain()  # must not raise


def test_verify_chain_detects_chain_hash_tamper(tmp_path):
    from mcp_armor.exceptions import AuditChainError

    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=False)
    ctx = make_ctx()

    engine._write("request", ctx, "tools/call", "d")
    engine._write("request", ctx, "tools/call", "d")

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

    engine._write("request", ctx, "tools/call", "d")
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
    from mcp_armor.types import MCPRequest
    from types import MappingProxyType

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
