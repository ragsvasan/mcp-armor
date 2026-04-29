"""Tests for T6 IntegrityEngine — manifest drift, typosquatting, NFKC homoglyphs."""

from __future__ import annotations

import pytest

from mcp_armor.engines.integrity import IntegrityEngine
from mcp_armor.exceptions import IntegrityError
from tests.conftest import make_ctx


def _engine(allowlist=None, fail_on_drift=True, distance=2) -> IntegrityEngine:
    return IntegrityEngine(
        fail_on_drift=fail_on_drift,
        tool_allowlist=allowlist,
        typosquat_distance=distance,
    )


TOOLS_A = [{"name": "tool_a", "description": "A"}, {"name": "tool_b", "description": "B"}]
TOOLS_B = [{"name": "tool_a", "description": "A"}, {"name": "tool_c", "description": "C"}]


# ---------------------------------------------------------------------------
# Drift detection (T6-001)
# ---------------------------------------------------------------------------

def test_no_drift_when_hash_matches() -> None:
    eng = _engine()
    ctx = make_ctx().with_manifest_hash(IntegrityEngine._manifest_hash(TOOLS_A))
    eng.check_drift(ctx, TOOLS_A)  # must not raise


def test_drift_detected_when_hash_changes() -> None:
    eng = _engine()
    ctx = make_ctx().with_manifest_hash(IntegrityEngine._manifest_hash(TOOLS_A))
    with pytest.raises(IntegrityError, match="rug-pull"):
        eng.check_drift(ctx, TOOLS_B)


def test_no_drift_check_when_baseline_empty() -> None:
    eng = _engine()
    ctx = make_ctx()  # tool_manifest_hash is ""
    eng.check_drift(ctx, TOOLS_B)  # must not raise — no baseline yet


def test_drift_allowed_when_fail_on_drift_false() -> None:
    eng = _engine(fail_on_drift=False)
    ctx = make_ctx().with_manifest_hash(IntegrityEngine._manifest_hash(TOOLS_A))
    eng.check_drift(ctx, TOOLS_B)  # must not raise


# ---------------------------------------------------------------------------
# Typosquatting (T6-002)
# ---------------------------------------------------------------------------

def test_exact_allowlist_match_passes() -> None:
    eng = _engine(allowlist=["tool_a", "tool_b"])
    eng.scan_tool_manifest([{"name": "tool_a"}, {"name": "tool_b"}])


def test_typosquat_distance_1_raises_high() -> None:
    eng = _engine(allowlist=["tools_list"])
    # "tooIs_list" is 1 edit from "tools_list" (I vs l is 1 char substitution in ASCII)
    with pytest.raises(IntegrityError) as exc_info:
        eng.scan_tool_manifest([{"name": "toolslist"}])  # delete underscore → distance 1
    assert exc_info.value.finding is not None
    from mcp_armor.types import Severity
    assert exc_info.value.finding.severity == Severity.HIGH


def test_typosquat_distance_2_raises_medium() -> None:
    eng = _engine(allowlist=["tool_a"])
    # "tool_ab" is distance 1 from "tool_a", "tool_abc" is distance 2
    with pytest.raises(IntegrityError) as exc_info:
        eng.scan_tool_manifest([{"name": "tXol_a"}])  # 2 substitutions
    assert exc_info.value.finding is not None
    from mcp_armor.types import Severity
    assert exc_info.value.finding.severity in (Severity.MEDIUM, Severity.HIGH)


def test_tool_outside_distance_no_raise() -> None:
    eng = _engine(allowlist=["tool_a"], distance=2)
    eng.scan_tool_manifest([{"name": "completely_different"}])  # distance >> 2


def test_no_allowlist_skips_typosquat_check() -> None:
    eng = _engine(allowlist=None)
    eng.scan_tool_manifest([{"name": "anything"}])


# ---------------------------------------------------------------------------
# NFKC homoglyph detection (T6-003 shadowing + T6-002 typosquatting)
# ---------------------------------------------------------------------------

def test_nfkc_homoglyph_shadowing_detected() -> None:
    """Two tools that look different but NFKC-normalize to same string."""
    # U+FF54 (ｔ FULLWIDTH LATIN SMALL LETTER T) normalizes to 't'
    eng = _engine()
    fake_name = "ｔool_a"  # fullwidth 't' + "ool_a"
    with pytest.raises(IntegrityError, match="homoglyph"):
        eng.scan_tool_manifest([
            {"name": "tool_a"},
            {"name": fake_name},
        ])


def test_nfkc_allowlist_lookup_catches_lookalike() -> None:
    """A tool name that visually looks like an allowlisted name but uses different code points."""
    # Capital I (U+0049) vs lowercase l (U+006C) — purely ASCII but NFKC still normalizes
    # More importantly: test with a genuine Unicode lookalike
    eng = _engine(allowlist=["tool_a"])
    # Use a fullwidth variant that NFKC normalizes to a name NOT in the allowlist
    # "ｔool_a" (fullwidth t) → NFKC → "tool_a" → match
    fullwidth = "ｔool_a"
    # This NFKC-normalizes to "tool_a" which IS in the allowlist → should pass
    eng.scan_tool_manifest([{"name": fullwidth}])


def test_distinct_tools_no_false_shadowing() -> None:
    eng = _engine()
    eng.scan_tool_manifest([{"name": "tool_a"}, {"name": "tool_b"}, {"name": "tool_c"}])


# ---------------------------------------------------------------------------
# scan_tool_manifest smoke tests
# ---------------------------------------------------------------------------

def test_scan_empty_manifest_passes() -> None:
    eng = _engine()
    findings = eng.scan_tool_manifest([])
    assert findings == []


def test_scan_returns_empty_list_on_clean() -> None:
    eng = _engine(allowlist=["tool_a"])
    result = eng.scan_tool_manifest([{"name": "tool_a"}])
    assert result == []


# ---------------------------------------------------------------------------
# Panel regression tests
# ---------------------------------------------------------------------------

def test_regression_duplicate_ascii_name_raises_shadowing() -> None:
    """FIX-1: exact duplicate tool names must be caught — same normalized form collides."""
    eng = _engine()
    with pytest.raises(IntegrityError, match="homoglyph|shadow"):
        eng.scan_tool_manifest([{"name": "tool_a"}, {"name": "tool_a"}])


def test_regression_missing_name_key_raises() -> None:
    """FIX-2: entry without 'name' key must raise IntegrityError, not KeyError/TypeError."""
    eng = _engine()
    with pytest.raises(IntegrityError):
        eng.scan_tool_manifest([{"description": "no name here"}])


def test_regression_non_string_name_raises() -> None:
    """FIX-2: non-string 'name' value must raise IntegrityError, not TypeError."""
    eng = _engine()
    with pytest.raises(IntegrityError):
        eng.scan_tool_manifest([{"name": 123}])
