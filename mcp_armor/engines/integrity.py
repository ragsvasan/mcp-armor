"""T6 — Integrity/Verification: manifest drift, typosquatting, tool shadowing."""

from __future__ import annotations

import hashlib
import json
import unicodedata

from ..context import CoSAIContext
from ..exceptions import IntegrityError
from ..types import MCPRequest, MCPResponse, Finding, Severity, ThreatCategory


def _nfkc(name: str) -> str:
    """NFKC-normalize a tool name to catch Unicode homoglyph attacks."""
    return unicodedata.normalize("NFKC", name)


class IntegrityEngine:
    """
    Snapshots the tools/list manifest at session start and detects drift.

    Covers:
    - T6-001: Mid-session tool list mutation (rug pull — tools added/removed)
    - T6-002: Tool name typosquatting against known-good allowlist
    - T6-003: Tool shadowing (two tools with near-identical Unicode names)

    Unicode homoglyph attacks (T11-ADV-001 class): NFKC normalization is applied to all
    tool names before Levenshtein comparison and before allowlist lookup.  A tool named
    ``tooIs_list`` (capital I replacing lowercase l) NFKC-normalizes to a string that
    either collides with an allowlist entry or lies within the typosquat threshold —
    caught by this engine independently of SupplyChainEngine.
    """

    def __init__(
        self,
        fail_on_drift: bool = True,
        tool_allowlist: list[str] | None = None,
        typosquat_distance: int = 2,
    ) -> None:
        self._fail_on_drift = fail_on_drift
        self._allowlist = (
            {_nfkc(n) for n in tool_allowlist} if tool_allowlist is not None else None
        )
        self._typosquat_distance = typosquat_distance

    @staticmethod
    def _manifest_hash(tools: list[dict]) -> str:
        canonical = json.dumps(sorted(tools, key=lambda t: t.get("name", "")), sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if len(a) < len(b):
            return IntegrityEngine._levenshtein(b, a)
        if not b:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a):
            curr = [i + 1]
            for j, cb in enumerate(b):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
            prev = curr
        return prev[-1]

    def _check_typosquat(self, name: str) -> None:
        """
        Check a tool name against the allowlist for typosquatting.

        Raises IntegrityError with severity HIGH if Levenshtein distance ≤ 1
        to any allowlist name (exact non-member is also caught here).
        Raises with severity MEDIUM if distance == 2 (within typosquat_distance).

        NFKC normalization is applied first — detects lookalike Unicode attacks.
        """
        if self._allowlist is None:
            return

        norm = _nfkc(name)
        if norm in self._allowlist:
            return  # exact match — OK

        for allowed in self._allowlist:
            dist = self._levenshtein(norm, allowed)
            if dist == 0:
                continue  # already handled above
            if dist <= 1:
                raise IntegrityError(
                    f"Tool '{name}' (normalized: '{norm}') is within Levenshtein distance 1 "
                    f"of allowlisted '{allowed}' — possible typosquatting (T6-002)",
                    finding=Finding(
                        threat=ThreatCategory.T6,
                        severity=Severity.HIGH,
                        code="T6-002",
                        message=f"Typosquat: '{name}' ≈ '{allowed}' (distance {dist})",
                        location="tool.name",
                        remediation="Remove or rename the tool to avoid allowlist collision",
                    ),
                )
            if dist <= self._typosquat_distance:
                raise IntegrityError(
                    f"Tool '{name}' (normalized: '{norm}') is within Levenshtein distance "
                    f"{dist} of allowlisted '{allowed}' — possible typosquatting (T6-002)",
                    finding=Finding(
                        threat=ThreatCategory.T6,
                        severity=Severity.MEDIUM,
                        code="T6-002",
                        message=f"Typosquat: '{name}' ≈ '{allowed}' (distance {dist})",
                        location="tool.name",
                        remediation="Verify this tool is from a trusted source",
                    ),
                )

    def _check_homoglyph_shadowing(self, tools: list[dict]) -> None:
        """
        Detect two tools whose NFKC-normalized names collide (tool shadowing).

        Example: 'tools_list' and 'tooIs_list' (capital I) both normalize to
        a form that is visually indistinguishable but occupies different code points.
        Also catches exact duplicates — two entries with the same name shadow each other.
        """
        seen: dict[str, str] = {}  # normalized_name → original_name
        for tool in tools:
            name = tool.get("name", "")
            if not isinstance(name, str) or not name:
                raise IntegrityError(
                    "Tool manifest contains an entry with a missing or non-string 'name' field"
                )
            norm = _nfkc(name)
            if norm in seen:
                raise IntegrityError(
                    f"Tool shadowing detected: '{name}' and '{seen[norm]}' have the same "
                    f"NFKC-normalized form '{norm}' — Unicode homoglyph attack (T6-003)"
                )
            seen[norm] = name

    async def on_startup(self) -> None:
        pass

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        return ctx

    def scan_tool_manifest(self, tools: list[dict]) -> list[Finding]:
        """
        Scan a tools/list response for integrity issues.

        Called by the guard after `tools/list` at session open.
        Raises IntegrityError on the first violation found.
        Also checks for homoglyph shadowing across the manifest.
        """
        self._check_homoglyph_shadowing(tools)
        for tool in tools:
            name = tool.get("name", "")
            if not isinstance(name, str) or not name:
                raise IntegrityError(
                    "Tool manifest contains an entry with a missing or non-string 'name' field"
                )
            self._check_typosquat(name)
        return []

    def check_drift(self, ctx: CoSAIContext, current_tools: list[dict]) -> None:
        """
        Compare the current tools manifest hash against the session baseline.

        Call this after every `tools/list` re-fetch during an active session.
        """
        new_hash = self._manifest_hash(current_tools)
        if ctx.tool_manifest_hash and new_hash != ctx.tool_manifest_hash:
            if self._fail_on_drift:
                raise IntegrityError(
                    f"Tool manifest changed mid-session "
                    f"(was {ctx.tool_manifest_hash[:12]}…, now {new_hash[:12]}…) — "
                    "possible rug-pull attack (T6-001)"
                )

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
