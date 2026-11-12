"""The tool gateway runtime: one governed MCP endpoint in front of all of the AI's tool servers.

Needs the ``mcp`` extra; the admin API (``--admin-port``) also needs ``server``.
"""

from quaicu.delivery.toolgate.gateway import MultiDownstream, ToolGateway

__all__ = ["MultiDownstream", "ToolGateway"]
