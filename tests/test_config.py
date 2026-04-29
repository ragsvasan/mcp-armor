"""Tests for config.py — load_config, unknown key rejection, ToolPolicy, ArmorConfig."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from mcp_armor.config import (
    ArmorConfig,
    ConfigError,
    T1Config,
    T2Config,
    ToolPolicy,
    load_config,
)


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "cosai.yaml"
    p.write_text(textwrap.dedent(content))
    return p


# ---------------------------------------------------------------------------
# Valid configs
# ---------------------------------------------------------------------------

def test_load_minimal(tmp_path: Path) -> None:
    # Absent threat block = enabled with defaults (fail-closed)
    p = _write(tmp_path, "version: 1\nthreats: {}\n")
    cfg = load_config(p)
    assert cfg.version == 1
    # All threats default-enabled with sensible defaults
    assert cfg.t1 is not None
    assert cfg.t1.require_dpop is True
    assert cfg.t2 is not None
    assert cfg.t2.default_deny is True


def test_load_t2_list_scopes(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        version: 1
        threats:
          T2:
            enabled: true
            default_policy: deny
            tool_policies:
              my_tool: [read:public]
    """)
    cfg = load_config(p)
    assert cfg.t2 is not None
    assert cfg.t2.tool_policies["my_tool"].required_scopes == ("read:public",)
    assert not cfg.t2.tool_policies["my_tool"].destructive


def test_load_t2_dict_policy(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        version: 1
        threats:
          T2:
            enabled: true
            default_policy: deny
            tool_policies:
              delete_user:
                required_scopes: [admin]
                destructive: true
                user_only: true
                tenant_isolated: true
    """)
    cfg = load_config(p)
    assert cfg.t2 is not None
    policy = cfg.t2.tool_policies["delete_user"]
    assert policy.required_scopes == ("admin",)
    assert policy.destructive
    assert policy.user_only
    assert policy.tenant_isolated


def test_load_t2_default_deny_allow(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        version: 1
        threats:
          T2:
            enabled: true
            default_policy: allow
            tool_policies: {}
    """)
    cfg = load_config(p)
    assert cfg.t2 is not None
    assert not cfg.t2.default_deny


def test_load_t1_all_fields(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        version: 1
        threats:
          T1:
            enabled: true
            require_dpop: false
            jti_cache_size: 500
            token_expiry_max_secs: 1800
            issuer: https://auth.example.com
            audience: mcp-server
    """)
    cfg = load_config(p)
    assert cfg.t1 is not None
    assert not cfg.t1.require_dpop
    assert cfg.t1.jti_cache_size == 500
    assert cfg.t1.issuer == "https://auth.example.com"


def test_load_disabled_threat_returns_none(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        version: 1
        threats:
          T1:
            enabled: false
    """)
    cfg = load_config(p)
    assert cfg.t1 is None


def test_load_t11_allowlist(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        version: 1
        threats:
          T11:
            enabled: true
            tool_allowlist: [tool_a, tool_b]
            levenshtein_threshold: 2
    """)
    cfg = load_config(p)
    assert cfg.t11 is not None
    assert cfg.t11.tool_allowlist == ("tool_a", "tool_b")
    assert cfg.t11.levenshtein_threshold == 2


def test_load_t11_empty_allowlist(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        version: 1
        threats:
          T11:
            enabled: true
            tool_allowlist: []
    """)
    cfg = load_config(p)
    assert cfg.t11 is not None
    # P1 fix: empty list must preserve as () (deny all), not collapse to None (allow all)
    assert cfg.t11.tool_allowlist == ()


def test_load_all_threats(tmp_path: Path) -> None:
    """smoke test — all 12 threats enabled with defaults."""
    lines = ["version: 1\nthreats:\n"]
    for i in range(1, 13):
        lines.append(f"  T{i}:\n    enabled: true\n")
    p = tmp_path / "cosai.yaml"
    p.write_text("".join(lines))
    cfg = load_config(p)
    assert cfg.t1 is not None
    assert cfg.t12 is not None


# ---------------------------------------------------------------------------
# Unknown-key rejection
# ---------------------------------------------------------------------------

def test_unknown_top_level_key_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, "version: 1\nthreats: {}\nextra_key: bad\n")
    with pytest.raises(ConfigError, match="extra_key"):
        load_config(p)


def test_unknown_threat_key_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, "version: 1\nthreats:\n  T99:\n    enabled: true\n")
    with pytest.raises(ConfigError, match="T99"):
        load_config(p)


def test_unknown_t1_field_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        version: 1
        threats:
          T1:
            enabled: true
            mystery_field: oops
    """)
    with pytest.raises(ConfigError, match="mystery_field"):
        load_config(p)


def test_unknown_t2_field_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, """
        version: 1
        threats:
          T2:
            enabled: true
            default_policy: deny
            tool_policies: {}
            rogue_key: bad
    """)
    with pytest.raises(ConfigError, match="rogue_key"):
        load_config(p)


def test_not_a_mapping_raises(tmp_path: Path) -> None:
    p = tmp_path / "cosai.yaml"
    p.write_text("- just a list\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_config(p)


# ---------------------------------------------------------------------------
# ToolPolicy.from_value edge cases
# ---------------------------------------------------------------------------

def test_tool_policy_invalid_type() -> None:
    with pytest.raises(ConfigError, match="int"):
        ToolPolicy.from_value(42)


def test_tool_policy_empty_scopes() -> None:
    p = ToolPolicy.from_value([])
    assert p.required_scopes == ()
    assert not p.destructive


# ---------------------------------------------------------------------------
# Context scopes propagation
# ---------------------------------------------------------------------------

def test_context_with_scopes() -> None:
    from mcp_armor.context import CoSAIContext
    ctx = CoSAIContext.new("sess-1")
    assert ctx.scopes == ()
    ctx2 = ctx.with_scopes(("read:public", "write:own"))
    assert ctx2.scopes == ("read:public", "write:own")
    assert ctx.scopes == ()  # original unchanged


# ---------------------------------------------------------------------------
# Codex P1: empty tool_allowlist preserved (not collapsed to None)
# ---------------------------------------------------------------------------

def test_regression_empty_t11_allowlist_preserved_not_allow_all(tmp_path: Path) -> None:
    """P1: tool_allowlist: [] must produce an empty tuple (deny all), not None (allow all)."""
    p = _write(tmp_path, """
        version: 1
        threats:
          T11:
            enabled: true
            tool_allowlist: []
    """)
    cfg = load_config(p)
    assert cfg.t11 is not None
    # Must be an empty tuple, not None — empty allowlist means deny all tools
    assert cfg.t11.tool_allowlist == ()


def test_regression_absent_t11_allowlist_is_none(tmp_path: Path) -> None:
    """P1: absent tool_allowlist key must remain None (no allowlist = allow all)."""
    p = _write(tmp_path, """
        version: 1
        threats:
          T11:
            enabled: true
    """)
    cfg = load_config(p)
    assert cfg.t11 is not None
    assert cfg.t11.tool_allowlist is None


def test_regression_empty_t6_allowlist_preserved_not_allow_all(tmp_path: Path) -> None:
    """P1: T6 tool_allowlist: [] must produce empty tuple (deny all), not None."""
    p = _write(tmp_path, """
        version: 1
        threats:
          T6:
            enabled: true
            tool_allowlist: []
    """)
    cfg = load_config(p)
    assert cfg.t6 is not None
    assert cfg.t6.tool_allowlist == ()
