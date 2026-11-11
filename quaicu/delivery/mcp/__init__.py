"""QUAICU MCP governance surface (D2-1).

`governance.py` is the reusable, MCP-dependency-free core (`govern_tool_call` / `ToolOutcome`).
`server.py` (registered tools) and `proxy.py` (front a downstream MCP server) build on it and import the
official ``mcp`` SDK lazily — install with ``pip install .[mcp]``.
"""

from quaicu.delivery.mcp.governance import ToolOutcome, ToolStatus, govern_tool_call

__all__ = ["ToolOutcome", "ToolStatus", "govern_tool_call"]
