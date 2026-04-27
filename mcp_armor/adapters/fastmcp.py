"""FastMCP adapter — wraps a FastMCP app with CoSAIGuard protection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..guard import CoSAIGuard


def wrap_fastmcp(app: Any, guard: "CoSAIGuard") -> Any:
    """
    Wrap a FastMCP application with mcp-armor protection.

    Usage:
        from cosai_server.adapters.fastmcp import wrap_fastmcp
        app = wrap_fastmcp(FastMCP("my-server"), guard)

    The wrapper intercepts tool dispatch at the FastMCP middleware layer,
    translating FastMCP request/response objects to MCPRequest/MCPResponse
    before passing through the guard chain.

    Requires: pip install mcp-armor[fastmcp]
    """
    try:
        import fastmcp  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "fastmcp is required for this adapter: pip install mcp-armor[fastmcp]"
        ) from exc

    # TODO: hook into fastmcp's middleware/dispatch mechanism
    # The specific API depends on the fastmcp version — implement once stable
    raise NotImplementedError(
        "FastMCP adapter is not yet implemented. "
        "Use guard.wrap_dispatcher() with a raw JSON-RPC dispatcher instead."
    )
