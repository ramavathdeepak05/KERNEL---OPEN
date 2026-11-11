"""``quaicu-kernel-mcp`` entrypoint — run the governed MCP surface from a kernel config.

Proxy mode (drop-in, no client/tool code change): builds the kernel from ``KERNEL_CONFIG``, connects to
a downstream MCP server, and serves its tools governed over stdio. Point your agent at THIS process
instead of the downstream.

    KERNEL_CONFIG=/etc/quaicu/kernel.gcp.toml quaicu-kernel-mcp

Config (in the kernel TOML)::

    [mcp]
    mode               = "proxy"
    agent_id           = "agent:mcp"          # the governance actor stamped on every tool call
    agent_roles        = ["agent"]
    default_policy     = "mcp.tool"           # CEL policy that governs the tool calls
    downstream_command = ["python", "-m", "my_tools_server"]   # the real MCP server to front

Server mode (registered tools) is programmatic — build a `GovernedMCPServer`, `register_tool(...)`, and
`await server.run_stdio()` from your own script (see quaicu/delivery/mcp/README.md).
"""

from __future__ import annotations

import asyncio
import os
import tomllib

from quaicu.core.types import Actor, ActorId
from quaicu.delivery.mcp.proxy import GovernedMCPProxy
from quaicu.delivery.sdk.kernel import Kernel


async def _run_proxy(config_path: str, mcp_cfg: dict) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    kernel = Kernel.from_config(config_path)
    await kernel.startup()
    try:
        actor = Actor(
            id=ActorId(str(mcp_cfg.get("agent_id", "agent:mcp"))),
            tenant=kernel.tenant,
            roles=tuple(str(r) for r in mcp_cfg.get("agent_roles", ())),
        )
        command = list(mcp_cfg.get("downstream_command") or [])
        if not command:
            raise SystemExit("[mcp] proxy mode requires downstream_command = [cmd, arg, ...].")
        params = StdioServerParameters(command=command[0], args=command[1:])
        async with stdio_client(params) as (d_read, d_write):
            async with ClientSession(d_read, d_write) as downstream:
                await downstream.initialize()
                proxy = GovernedMCPProxy(
                    kernel,
                    actor=actor,
                    downstream=downstream,
                    default_policy=str(mcp_cfg.get("default_policy", "mcp.tool")),
                )
                from mcp.server.stdio import stdio_server

                server = proxy.build_mcp_server()
                async with stdio_server() as (read, write):
                    await server.run(read, write, server.create_initialization_options())
    finally:
        await kernel.shutdown()


def main() -> None:
    config_path = os.getenv("KERNEL_CONFIG", "kernel.toml")
    with open(config_path, "rb") as f:
        cfg = tomllib.load(f)
    mcp_cfg = cfg.get("mcp", {})
    mode = str(mcp_cfg.get("mode", "proxy"))
    if mode != "proxy":
        raise SystemExit(
            "server mode is programmatic — build a GovernedMCPServer, register_tool(...), and "
            "await server.run_stdio() (see quaicu/delivery/mcp/README.md). Set [mcp] mode = \"proxy\" to "
            "front a downstream MCP server from this entrypoint."
        )
    asyncio.run(_run_proxy(config_path, mcp_cfg))


if __name__ == "__main__":
    main()
