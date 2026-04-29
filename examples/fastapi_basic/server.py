"""FastAPI basic example — ArmorMiddleware on a raw JSON-RPC dispatcher."""

import json
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from mcp_armor import CoSAIGuard
from mcp_armor.adapters.fastapi import ArmorMiddleware

inner_app = FastAPI(title="MCP Server (inner)")
guard = CoSAIGuard.from_config("cosai.yaml")
app = ArmorMiddleware(inner_app, guard)


@inner_app.post("/")
async def dispatch(request: Request) -> JSONResponse:
    body = await request.json()
    method = body.get("method", "")

    if method == "tools/list":
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {
                "tools": [
                    {"name": "echo", "description": "Echo input", "inputSchema": {
                        "type": "object",
                        "properties": {"message": {"type": "string"}},
                        "required": ["message"],
                    }},
                ]
            },
        })

    if method == "tools/call":
        name = body.get("params", {}).get("name")
        args = body.get("params", {}).get("arguments", {})
        if name == "echo":
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {"content": [{"type": "text", "text": f"Echo: {args.get('message', '')}"}]},
            })

    return JSONResponse({
        "jsonrpc": "2.0",
        "id": body.get("id"),
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    })


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
