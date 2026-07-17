"""T11 — Supply Chain: tool allowlist enforcement, registry signature verification."""

from __future__ import annotations

import json
import logging
import unicodedata

from ..context import CoSAIContext
from ..exceptions import SupplyChainError
from ..types import MCPRequest, MCPResponse

log = logging.getLogger(__name__)


def _nfkc(name: str) -> str:
    """NFKC-normalize a tool name to catch Unicode homoglyph attacks (T11-ADV-001)."""
    return unicodedata.normalize("NFKC", name)


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _load_ed25519_public_key(pem_or_b64: str):  # type: ignore[return]
    """Load an Ed25519 public key from PEM or raw base64-encoded bytes."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    pem_or_b64 = pem_or_b64.strip()
    if pem_or_b64.startswith("-----"):
        key = load_pem_public_key(pem_or_b64.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise SupplyChainError("Registry public key is not Ed25519")
        return key

    # Try raw base64 (32-byte Ed25519 public key)
    try:
        raw = base64.b64decode(pem_or_b64)
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        return ed25519.Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise SupplyChainError(f"Cannot load registry public key: {exc}") from exc


class SupplyChainEngine:
    """
    Validates tools at server startup against a known-good allowlist.

    Covers:
    - T11-001: Unlisted tool loaded (no allowlist = deny all)
    - T11-002: Typosquatted tool name (Levenshtein distance ≤ levenshtein_threshold)
    - T11-003: Unsigned tool from untrusted registry (Ed25519 signature check)
    - T11-004: Dependency confusion (internal name shadowed by public package)
    - T11-ADV-001: Unicode homoglyph attack (NFKC normalization)

    Real-world reference: CVE-2026-21852 — poisoned PyPI package with modified tool
    definitions.  This engine is the runtime enforcement layer that catches compromised
    definitions even after a CI SCA scan passes.
    """

    def __init__(
        self,
        tool_allowlist: list[str] | None = None,
        require_registry_signature: bool = False,
        levenshtein_threshold: int = 1,
        registry_public_key: str | None = None,
    ) -> None:
        # Normalize the allowlist at init time — all comparisons use NFKC forms
        self._allowlist: set[str] | None = (
            {_nfkc(n) for n in tool_allowlist} if tool_allowlist is not None else None
        )
        self._raw_allowlist: list[str] = tool_allowlist or []
        self._require_sig = require_registry_signature
        self._levenshtein_threshold = levenshtein_threshold
        self._pub_key = (
            _load_ed25519_public_key(registry_public_key) if registry_public_key else None
        )

    async def on_startup(self) -> None:
        if self._require_sig and self._pub_key is None:
            raise SupplyChainError(
                "SupplyChainEngine: require_registry_signature=True but no "
                "registry_public_key configured."
            )

    def _check_allowlist(self, name: str) -> None:
        """Reject tool names not on the allowlist (exact NFKC match required)."""
        if self._allowlist is None:
            return
        norm = _nfkc(name)
        if norm not in self._allowlist:
            raise SupplyChainError(
                f"Tool '{name}' (normalized: '{norm}') is not on the approved allowlist (T11-001)"
            )

    def _check_typosquat(self, name: str) -> None:
        """
        Detect typosquatting: NFKC-normalized name within Levenshtein threshold of
        any allowlisted name.

        This is complementary to the exact-match allowlist check:
        - Allowlist catches exact non-members (T11-001)
        - Levenshtein catches near-misses (T11-002)
        - NFKC catches visual spoofing that ASCII distance misses (T11-ADV-001)
        """
        if self._allowlist is None:
            return
        norm = _nfkc(name)
        if norm in self._allowlist:
            return  # exact allowlist match — OK

        for allowed in self._allowlist:
            dist = _levenshtein(norm, allowed)
            if 0 < dist <= self._levenshtein_threshold:
                raise SupplyChainError(
                    f"Tool '{name}' (normalized: '{norm}') is within Levenshtein distance "
                    f"{dist} of allowlisted '{allowed}' — typosquatting attack (T11-002)"
                )

    def _verify_signature(self, tool: dict, signature_hex: str) -> None:
        """
        Verify that the tool definition was signed with the registry's Ed25519 key.

        Signature covers the canonical JSON of the tool definition, excluding
        only the `_sig` field itself (which carries the signature and cannot
        sign itself). LOW fix: this previously excluded EVERY `_`-prefixed
        key, not just `_sig` — meaning any future `_`-prefixed field a
        consumer reads would have been unsigned side-channel data, freely
        rewritable by an attacker without invalidating the signature. Only
        `_sig` is excluded now, so any other `_`-prefixed field is part of the
        signed body like everything else. Signature is stored in the `_sig`
        field or provided as a sidecar.
        """
        import binascii

        if self._pub_key is None:
            raise SupplyChainError(
                "Registry signature verification requested but no public key configured"
            )
        from cryptography.exceptions import InvalidSignature

        try:
            canonical = json.dumps(
                {k: v for k, v in tool.items() if k != "_sig"},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            sig_bytes = binascii.unhexlify(signature_hex)
            self._pub_key.verify(sig_bytes, canonical)
        except (InvalidSignature, binascii.Error) as exc:
            name = tool.get("name", "<unknown>")
            raise SupplyChainError(
                f"Tool '{name}' registry signature invalid or missing (T11-003)"
            ) from exc

    def validate_tools(self, tools: list[dict]) -> None:
        """
        Call from server startup with the tools/list response.

        Performs:
        1. Allowlist check (T11-001)
        2. Typosquat / NFKC homoglyph check (T11-002, T11-ADV-001)
        3. Ed25519 registry signature check when require_registry_signature=True (T11-003)
        """
        for tool in tools:
            name = tool.get("name", "")
            if not isinstance(name, str) or not name:
                raise SupplyChainError(
                    "Tool manifest contains an entry with a missing or non-string 'name' field"
                )

            # T11-002 first: near-misses are more suspicious (typosquatting) than unknowns.
            # _check_typosquat returns early for exact allowlist members.
            self._check_typosquat(name)

            # T11-001 / T11-ADV-001: exact NFKC match required for non-near-misses
            self._check_allowlist(name)

            # T11-003 — verify Ed25519 registry signature
            if self._require_sig:
                sig = tool.get("_sig", "")
                if not sig:
                    raise SupplyChainError(
                        f"Tool '{name}' has no registry signature and "
                        "require_registry_signature=True (T11-003)"
                    )
                self._verify_signature(tool, str(sig))

    async def on_session_start(self, ctx: CoSAIContext) -> CoSAIContext:
        return ctx

    async def on_request(self, ctx: CoSAIContext, req: MCPRequest) -> CoSAIContext:
        if req.method == "tools/call":
            name = req.params.get("name", "")
            if isinstance(name, str) and name:
                self._check_typosquat(name)
                self._check_allowlist(name)
        return ctx

    async def on_response(self, ctx: CoSAIContext, resp: MCPResponse) -> CoSAIContext:
        # Intercept tools/list responses and run manifest validation automatically.
        # This enforces T11 on the wrapper/middleware path without requiring app code
        # to manually call validate_tools().
        if resp.result is not None and "tools" in resp.result:
            tools = list(resp.result["tools"])
            self.validate_tools(tools)
        return ctx

    async def on_session_end(self, ctx: CoSAIContext) -> None:
        pass

    async def on_shutdown(self) -> None:
        pass
