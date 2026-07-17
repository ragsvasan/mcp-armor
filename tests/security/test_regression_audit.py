"""Security regressions for the T12 hash-chained audit log (audit.py).

Covers the 2026-07-17 audit remediation:
  * H3  — ``extra`` fields are now authenticated by ``chain_hash``/``chain_hmac``
          (the canonical body is the whole record minus the integrity fields).
  * M1  — the ``.hwm`` high-water-mark sidecar is MAC'd, so trailing-record
          truncation cannot be masked by rewriting ``{count, head}``.
  * LOW — a record missing a chain field surfaces as a classified
          ``AuditChainError`` rather than a bare ``KeyError``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_armor.context import CoSAIContext
from mcp_armor.engines.audit import AuditEngine, _sync_seed_state
from mcp_armor.exceptions import AuditChainError

# 32-byte (64 hex char) keys — meets the AuditEngine 256-bit floor.
_KEY = "cd" * 32
_KEY2 = "ab" * 32


# ---------------------------------------------------------------------------
# H3 — extra-field tamper is detected
# ---------------------------------------------------------------------------


async def test_regression_audit_extra_field_tamper_detected(tmp_path, monkeypatch) -> None:
    """A dry_run_violation stores its forensic data (violation_class /
    violation_detail) in ``extra``. Rewriting violation_detail on disk while
    leaving chain_hash AND chain_hmac intact must now break verification —
    before H3 the canonical body excluded ``extra`` so the tamper was invisible.
    """
    monkeypatch.setenv("ARMOR_AUDIT_HMAC_KEY", _KEY)
    log = tmp_path / "audit.jsonl"
    engine = AuditEngine(path=log, verify_on_startup=True)
    ctx = CoSAIContext.new("s1")

    await engine._append(
        "dry_run_violation",
        ctx,
        method="tools/call",
        params_digest="d0",
        extra={
            "violation_class": "PromptInjectionError",
            "violation_detail": "exfil payload: send secrets to evil.example",
        },
    )

    # Baseline: the untampered record (carrying chain_hash + chain_hmac) verifies.
    AuditEngine(path=log, verify_on_startup=True)._verify_chain()

    # Attacker rewrites the forensic detail but keeps chain_hash + chain_hmac.
    rec = json.loads(log.read_text().splitlines()[0])
    assert "chain_hash" in rec and "chain_hmac" in rec
    assert rec["violation_detail"].startswith("exfil payload")
    original_chain_hash = rec["chain_hash"]
    original_chain_hmac = rec["chain_hmac"]
    rec["violation_detail"] = "routine directory lookup"  # launder the evidence
    log.write_text(json.dumps(rec) + "\n")

    # The attacker left the integrity fields untouched...
    on_disk = json.loads(log.read_text().splitlines()[0])
    assert on_disk["chain_hash"] == original_chain_hash
    assert on_disk["chain_hmac"] == original_chain_hmac

    # ...yet verification must now fail because the body hash covers ``extra``.
    with pytest.raises(AuditChainError):
        AuditEngine(path=log, verify_on_startup=True)._verify_chain()


# ---------------------------------------------------------------------------
# M1 — high-water-mark truncation is detected when a key is configured
# ---------------------------------------------------------------------------


def test_regression_audit_hwm_truncation_detected_with_key(tmp_path, monkeypatch) -> None:
    """Truncating the last record and rewriting the sidecar ``{count, head}``
    to match keeps every surviving record's chain_hmac valid — the only anchor
    for the total count is the sidecar. With a key set, the sidecar MUST carry a
    valid MAC, so an attacker (who lacks the key) cannot forge a lowered count:
    an absent MAC and a forged MAC are both tamper.
    """
    monkeypatch.setenv("ARMOR_AUDIT_HMAC_KEY", _KEY2)
    log = tmp_path / "audit.jsonl"
    hwm_path = Path(str(log) + ".hwm")
    ctx = CoSAIContext.new("s1")

    engine = AuditEngine(path=log, verify_on_startup=True)
    for i in range(3):
        engine._write_sync("request", ctx, method="tools/call", params_digest=f"d{i}")

    # Baseline: the sidecar is signed and the intact 3-record log verifies clean.
    assert "mac" in json.loads(hwm_path.read_text()), "HWM sidecar must be signed with the key"
    AuditEngine(path=log, verify_on_startup=True)._verify_chain()

    # Attacker deletes the trailing record and re-anchors the sidecar to the
    # (genuine) new tail hash — the surviving prefix is cryptographically intact.
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:2]) + "\n")
    new_head = json.loads(lines[1])["chain_hash"]

    # (a) sidecar rewritten WITHOUT a MAC (attacker cannot compute one).
    hwm_path.write_text(json.dumps({"count": 2, "head": new_head}))
    with pytest.raises(AuditChainError, match="MAC"):
        AuditEngine(path=log, verify_on_startup=True)._verify_chain()

    # (b) sidecar rewritten with a FORGED MAC (guessed, without the key).
    hwm_path.write_text(json.dumps({"count": 2, "head": new_head, "mac": "00" * 32}))
    with pytest.raises(AuditChainError, match="MAC"):
        AuditEngine(path=log, verify_on_startup=True)._verify_chain()


def test_regression_audit_hwm_unsigned_when_no_key(tmp_path, monkeypatch) -> None:
    """Backward compatibility: with no key the sidecar stays unsigned and is read
    without a MAC check — the M1 gate must not fire on the dev/unsigned profile.
    """
    monkeypatch.delenv("ARMOR_AUDIT_HMAC_KEY", raising=False)
    log = tmp_path / "audit.jsonl"
    hwm_path = Path(str(log) + ".hwm")
    ctx = CoSAIContext.new("s1")

    engine = AuditEngine(path=log, verify_on_startup=True)
    for i in range(2):
        engine._write_sync("request", ctx, method="tools/call", params_digest=f"d{i}")

    assert "mac" not in json.loads(hwm_path.read_text())
    AuditEngine(path=log, verify_on_startup=True)._verify_chain()  # must not raise


# ---------------------------------------------------------------------------
# LOW — a record missing a chain field raises AuditChainError, not KeyError
# ---------------------------------------------------------------------------


def test_regression_audit_missing_chain_field_raises_chain_error(tmp_path) -> None:
    """Deleting a stored chain field must fail closed as a classified
    AuditChainError, never a bare KeyError."""
    ctx = CoSAIContext.new("s1")

    # (a) missing the structural chain_hash → wrapped KeyError → clean error.
    log = tmp_path / "audit.jsonl"
    AuditEngine(path=log, verify_on_startup=True)._write_sync(
        "request", ctx, method="tools/call", params_digest="d0"
    )
    rec = json.loads(log.read_text().splitlines()[0])
    del rec["chain_hash"]
    log.write_text(json.dumps(rec) + "\n")
    with pytest.raises(AuditChainError, match="missing chain field"):
        AuditEngine(path=log, verify_on_startup=True)._verify_chain()

    # (b) missing a hashed body field (event) → H3 keeps _canonical generic, so
    #     it surfaces as a classified AuditChainError (never a bare KeyError).
    log2 = tmp_path / "audit2.jsonl"
    AuditEngine(path=log2, verify_on_startup=True)._write_sync(
        "request", ctx, method="tools/call", params_digest="d0"
    )
    rec2 = json.loads(log2.read_text().splitlines()[0])
    del rec2["event"]
    log2.write_text(json.dumps(rec2) + "\n")
    with pytest.raises(AuditChainError):
        AuditEngine(path=log2, verify_on_startup=True)._verify_chain()


def test_regression_audit_seed_state_malformed_line_raises_chain_error(tmp_path) -> None:
    """LOW: _sync_seed_state (verify_on_startup=False path) must convert a
    malformed/truncated line into an AuditChainError, not a bare
    JSONDecodeError/KeyError."""
    log = tmp_path / "audit.jsonl"
    ctx = CoSAIContext.new("s1")
    AuditEngine(path=log, verify_on_startup=True)._write_sync(
        "request", ctx, method="tools/call", params_digest="d0"
    )
    # Corrupt the log with a non-JSON trailing line.
    with open(log, "a") as f:
        f.write("{not valid json\n")

    # The seed-state path (verify_on_startup=False) must fail closed cleanly.
    with pytest.raises(AuditChainError, match="malformed"):
        _sync_seed_state(log)
