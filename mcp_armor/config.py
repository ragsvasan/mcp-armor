"""Typed, frozen configuration objects for mcp-armor. Loaded from cosai.yaml."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)


class ConfigError(ValueError):
    """Raised when cosai.yaml contains unknown keys or invalid values."""


# ---------------------------------------------------------------------------
# Known key sets for each threat block — unknown keys are rejected at load
# ---------------------------------------------------------------------------

_KNOWN_TOP_LEVEL = frozenset({"version", "threats"})
_KNOWN_THREAT_KEYS = frozenset({f"T{i}" for i in range(1, 13)})

_KNOWN_T1 = frozenset({
    "enabled", "require_dpop", "jti_cache_size", "token_expiry_max_secs",
    "jwks", "issuer", "audience", "endpoint_uri", "dpop_max_age_secs",
    "dpop_future_skew_secs",
})
_KNOWN_T2 = frozenset({
    "enabled", "default_policy", "tool_policies", "destructive_token_ttl_seconds",
})
_KNOWN_T3 = frozenset({"enabled", "max_payload_bytes", "strict_schema"})
_KNOWN_T4 = frozenset({"enabled", "scan_definitions", "scan_responses", "scan_call_args"})
_KNOWN_T5 = frozenset({"enabled", "profile"})
_KNOWN_T6 = frozenset({
    "enabled", "baseline_on_initialize", "fail_on_drift", "tool_allowlist", "typosquat_distance",
})
_KNOWN_T7 = frozenset({"enabled", "bind_session_to_dpop"})
_KNOWN_T8 = frozenset({"enabled", "allow_public_bind", "block_rfc1918"})
_KNOWN_T9 = frozenset({"enabled", "max_output_length", "strip_injection_patterns"})
_KNOWN_T10 = frozenset({
    "enabled", "max_calls_per_session", "max_wall_clock_secs",
    "loop_depth_limit", "heartbeat_interval_secs",
})
_KNOWN_T11 = frozenset({
    "enabled", "tool_allowlist", "require_registry_signature", "levenshtein_threshold",
    "registry_public_key",
})
_KNOWN_T12 = frozenset({"enabled", "path", "log_params_as_digest", "chain_verify_on_startup"})

_KNOWN_BY_THREAT: dict[str, frozenset[str]] = {
    "T1": _KNOWN_T1, "T2": _KNOWN_T2, "T3": _KNOWN_T3, "T4": _KNOWN_T4,
    "T5": _KNOWN_T5, "T6": _KNOWN_T6, "T7": _KNOWN_T7, "T8": _KNOWN_T8,
    "T9": _KNOWN_T9, "T10": _KNOWN_T10, "T11": _KNOWN_T11, "T12": _KNOWN_T12,
}


def _reject_unknown(d: dict[str, Any], known: frozenset[str], ctx: str) -> None:
    unknown = set(d.keys()) - known
    if unknown:
        raise ConfigError(f"Unknown config keys in {ctx}: {sorted(unknown)}")


# ---------------------------------------------------------------------------
# Per-tool policy (T2)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolPolicy:
    required_scopes: tuple[str, ...]
    user_only: bool
    destructive: bool
    tenant_isolated: bool

    @classmethod
    def from_value(cls, v: Any) -> "ToolPolicy":
        """
        Accept two formats:
          - list of scope strings (legacy): ["read:public"]
          - dict with explicit fields: {required_scopes: [...], destructive: true, ...}
        """
        if isinstance(v, list):
            return cls(
                required_scopes=tuple(str(s) for s in v),
                user_only=False,
                destructive=False,
                tenant_isolated=False,
            )
        if isinstance(v, dict):
            return cls(
                required_scopes=tuple(str(s) for s in v.get("required_scopes", [])),
                user_only=bool(v.get("user_only", False)),
                destructive=bool(v.get("destructive", False)),
                tenant_isolated=bool(v.get("tenant_isolated", False)),
            )
        raise ConfigError(
            f"tool_policies entry must be a list of scopes or a dict, got {type(v).__name__}"
        )


# ---------------------------------------------------------------------------
# Per-threat config dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class T1Config:
    require_dpop: bool = True
    jti_cache_size: int = 10_000
    token_expiry_max_secs: int = 3600
    jwks: dict[str, Any] | None = None
    issuer: str | None = None
    audience: str | None = None
    endpoint_uri: str | None = None
    dpop_max_age_secs: int = 30
    dpop_future_skew_secs: int = 5


@dataclass(frozen=True)
class T2Config:
    tool_policies: dict[str, ToolPolicy]
    default_deny: bool = True
    destructive_token_ttl_seconds: int = 60


@dataclass(frozen=True)
class T3Config:
    max_payload_bytes: int = 65_536
    strict_schema: bool = True


@dataclass(frozen=True)
class T4Config:
    scan_definitions: bool = True
    scan_responses: bool = True
    scan_call_args: bool = True


@dataclass(frozen=True)
class T5Config:
    profile: str = "pci"


@dataclass(frozen=True)
class T6Config:
    fail_on_drift: bool = True
    tool_allowlist: tuple[str, ...] | None = None
    typosquat_distance: int = 2


@dataclass(frozen=True)
class T7Config:
    bind_to_dpop: bool = True


@dataclass(frozen=True)
class T8Config:
    allow_public_bind: bool = False
    block_rfc1918_ssrf: bool = True


@dataclass(frozen=True)
class T9Config:
    max_output_length: int = 32_768
    strip_injection_patterns: bool = True


@dataclass(frozen=True)
class T10Config:
    max_calls_per_session: int = 100
    max_wall_clock_secs: int = 300
    loop_depth_limit: int = 10
    heartbeat_interval_secs: int = 30


@dataclass(frozen=True)
class T11Config:
    tool_allowlist: tuple[str, ...] | None = None
    require_registry_signature: bool = False
    levenshtein_threshold: int = 1
    registry_public_key: str | None = None


@dataclass(frozen=True)
class T12Config:
    path: str = "/var/log/mcp-armor/audit.jsonl"
    chain_verify_on_startup: bool = True


@dataclass(frozen=True)
class ArmorConfig:
    version: int
    t1: T1Config | None
    t2: T2Config | None
    t3: T3Config | None
    t4: T4Config | None
    t5: T5Config | None
    t6: T6Config | None
    t7: T7Config | None
    t8: T8Config | None
    t9: T9Config | None
    t10: T10Config | None
    t11: T11Config | None
    t12: T12Config | None


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(path: str | Path) -> ArmorConfig:
    """Load, validate, and return a typed ArmorConfig from cosai.yaml."""
    with open(path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ConfigError("cosai.yaml must be a YAML mapping")

    _reject_unknown(raw, _KNOWN_TOP_LEVEL, "top-level")

    version = int(raw.get("version", 1))
    threats: dict[str, Any] = raw.get("threats", {})

    if not isinstance(threats, dict):
        raise ConfigError("'threats' must be a mapping")

    unknown_threats = set(threats.keys()) - _KNOWN_THREAT_KEYS
    if unknown_threats:
        raise ConfigError(f"Unknown threat keys: {sorted(unknown_threats)}")

    def _t(key: str) -> dict[str, Any] | None:
        """Return the raw threat block if enabled, else None."""
        block = threats.get(key, {})
        if not isinstance(block, dict):
            raise ConfigError(f"{key} config must be a mapping")
        if not block.get("enabled", True):
            return None
        _reject_unknown(block, _KNOWN_BY_THREAT[key], key)
        return block

    # T1
    t1_raw = _t("T1")
    t1 = T1Config(
        require_dpop=t1_raw.get("require_dpop", True),
        jti_cache_size=int(t1_raw.get("jti_cache_size", 10_000)),
        token_expiry_max_secs=int(t1_raw.get("token_expiry_max_secs", 3600)),
        jwks=t1_raw.get("jwks"),
        issuer=t1_raw.get("issuer"),
        audience=t1_raw.get("audience"),
        endpoint_uri=t1_raw.get("endpoint_uri"),
        dpop_max_age_secs=int(t1_raw.get("dpop_max_age_secs", 30)),
        dpop_future_skew_secs=int(t1_raw.get("dpop_future_skew_secs", 5)),
    ) if t1_raw is not None else None

    # T2
    t2_raw = _t("T2")
    t2: T2Config | None = None
    if t2_raw is not None:
        raw_policies = t2_raw.get("tool_policies") or {}
        policies: dict[str, ToolPolicy] = {
            name: ToolPolicy.from_value(v) for name, v in raw_policies.items()
        }
        t2 = T2Config(
            tool_policies=policies,
            default_deny=t2_raw.get("default_policy", "deny") == "deny",
            destructive_token_ttl_seconds=int(t2_raw.get("destructive_token_ttl_seconds", 60)),
        )

    # T3
    t3_raw = _t("T3")
    t3 = T3Config(
        max_payload_bytes=int(t3_raw.get("max_payload_bytes", 65_536)),
        strict_schema=bool(t3_raw.get("strict_schema", True)),
    ) if t3_raw is not None else None

    # T4
    t4_raw = _t("T4")
    t4 = T4Config(
        scan_definitions=bool(t4_raw.get("scan_definitions", True)),
        scan_responses=bool(t4_raw.get("scan_responses", True)),
        scan_call_args=bool(t4_raw.get("scan_call_args", True)),
    ) if t4_raw is not None else None

    # T5
    t5_raw = _t("T5")
    t5 = T5Config(profile=str(t5_raw.get("profile", "pci"))) if t5_raw is not None else None

    # T6
    t6_raw = _t("T6")
    t6_allowlist = None
    if t6_raw is not None:
        raw_al = t6_raw.get("tool_allowlist")
        t6_allowlist = tuple(raw_al) if raw_al else None
    t6 = T6Config(
        fail_on_drift=bool(t6_raw.get("fail_on_drift", True)),
        tool_allowlist=t6_allowlist,
        typosquat_distance=int(t6_raw.get("typosquat_distance", 2)),
    ) if t6_raw is not None else None

    # T7
    t7_raw = _t("T7")
    t7 = T7Config(
        bind_to_dpop=bool(t7_raw.get("bind_session_to_dpop", True)),
    ) if t7_raw is not None else None

    # T8
    t8_raw = _t("T8")
    t8 = T8Config(
        allow_public_bind=bool(t8_raw.get("allow_public_bind", False)),
        block_rfc1918_ssrf=bool(t8_raw.get("block_rfc1918", True)),
    ) if t8_raw is not None else None

    # T9
    t9_raw = _t("T9")
    t9 = T9Config(
        max_output_length=int(t9_raw.get("max_output_length", 32_768)),
        strip_injection_patterns=bool(t9_raw.get("strip_injection_patterns", True)),
    ) if t9_raw is not None else None

    # T10
    t10_raw = _t("T10")
    t10 = T10Config(
        max_calls_per_session=int(t10_raw.get("max_calls_per_session", 100)),
        max_wall_clock_secs=int(t10_raw.get("max_wall_clock_secs", 300)),
        loop_depth_limit=int(t10_raw.get("loop_depth_limit", 10)),
        heartbeat_interval_secs=int(t10_raw.get("heartbeat_interval_secs", 30)),
    ) if t10_raw is not None else None

    # T11
    t11_raw = _t("T11")
    t11: T11Config | None = None
    if t11_raw is not None:
        raw_al11 = t11_raw.get("tool_allowlist")
        t11_allowlist = tuple(raw_al11) if raw_al11 else None
        t11 = T11Config(
            tool_allowlist=t11_allowlist,
            require_registry_signature=bool(t11_raw.get("require_registry_signature", False)),
            levenshtein_threshold=int(t11_raw.get("levenshtein_threshold", 1)),
            registry_public_key=t11_raw.get("registry_public_key"),
        )

    # T12
    t12_raw = _t("T12")
    t12 = T12Config(
        path=str(t12_raw.get("path", "/var/log/mcp-armor/audit.jsonl")),
        chain_verify_on_startup=bool(t12_raw.get("chain_verify_on_startup", True)),
    ) if t12_raw is not None else None

    return ArmorConfig(
        version=version,
        t1=t1, t2=t2, t3=t3, t4=t4,
        t5=t5, t6=t6, t7=t7, t8=t8,
        t9=t9, t10=t10, t11=t11, t12=t12,
    )
