"""FastMCP basic example — wrap a FastMCP server with mcp-armor."""

from fastmcp import FastMCP
from mcp_armor import CoSAIGuard
from mcp_armor.adapters.fastmcp import wrap_fastmcp

app = FastMCP("secure-demo")
guard = CoSAIGuard.from_config("cosai.yaml")
protected = wrap_fastmcp(app, guard)


@app.tool()
async def echo(message: str) -> str:
    """Echo the input message back."""
    return f"Echo: {message}"


@app.tool()
async def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(protected, host="127.0.0.1", port=8000)
