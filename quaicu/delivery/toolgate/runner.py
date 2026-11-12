"""Run the tool gateway: ``quaicu gateway``.

Starts every ``[[tools.server]]`` as a child process with its credentials, serves the governed tools
to the AI over stdio (MCP), and — with ``--admin-port`` — serves the kernel's REST API on 127.0.0.1
in the same process. Approvals (``/v1/approvals``) and live guardrail changes (``/v1/tools``) then
act on the running gateway, even with the in-memory starter configuration.

stdout belongs to the MCP protocol: everything else (logs, the generated admin token) goes to stderr.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sys
import tomllib
from pathlib import Path
from typing import Any

from quaicu.core.toolgate import ToolConfigError, parse_tools_config
from quaicu.delivery.sdk.kernel import Kernel, expand_env

log = logging.getLogger("quaicu.toolgate")


def load_gateway_config(path: str | Path) -> tuple[dict[str, Any], Any]:
    """Read kernel.toml (with ``${VAR}`` expansion) and parse its ``[tools]`` section."""
    with open(path, "rb") as f:
        cfg = expand_env(tomllib.load(f))
    return cfg, parse_tools_config(cfg)


async def _open_sessions(stack: contextlib.AsyncExitStack, servers) -> dict[str, Any]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    sessions: dict[str, Any] = {}
    for spec in servers:
        params = StdioServerParameters(
            command=spec.command[0], args=list(spec.command[1:]), env=dict(spec.env) or None
        )
        try:
            read, write = await stack.enter_async_context(stdio_client(params, errlog=sys.stderr))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
        except Exception as exc:  # noqa: BLE001 — refuse to start rather than run half-configured
            raise RuntimeError(f"tool server {spec.name!r} failed to start: {exc}") from exc
        sessions[spec.name] = session
        log.info("tool server %r started", spec.name)
    return sessions


def _admin_server(kernel: Kernel, host: str, port: int):
    import uvicorn

    from quaicu.delivery.api.app import create_app

    config = uvicorn.Config(
        create_app(kernel), host=host, port=port, log_config=None, access_log=False, lifespan="on"
    )
    server = uvicorn.Server(config)
    # The gateway owns the process: the MCP loop ending (stdin closed, Ctrl-C) stops this server.
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    return server


async def run_gateway(config_path: str | Path, *, admin_port: int | None = None, admin_host: str = "127.0.0.1") -> None:
    from mcp.server.lowlevel import NotificationOptions
    from mcp.server.stdio import stdio_server

    from quaicu.delivery.toolgate.gateway import ToolGateway

    _cfg, gw_config = load_gateway_config(config_path)
    kernel = Kernel.from_config(config_path)
    admin = None
    admin_task: asyncio.Task | None = None
    async with contextlib.AsyncExitStack() as stack:
        sessions = await _open_sessions(stack, gw_config.servers)
        gateway = ToolGateway(kernel, gw_config, sessions)
        if admin_port:
            # The admin app's lifespan runs kernel.startup()/shutdown().
            admin = _admin_server(kernel, admin_host, admin_port)
            admin_task = asyncio.create_task(admin.serve())
            log.info("admin API on http://%s:%d (/v1/tools, /v1/approvals)", admin_host, admin_port)
        else:
            await kernel.startup()
        server = gateway.build_mcp_server()
        options = server.create_initialization_options(
            notification_options=NotificationOptions(tools_changed=True)
        )
        try:
            async with stdio_server() as (read, write):
                await server.run(read, write, options)
        finally:
            if admin_task is not None:
                admin.should_exit = True  # graceful: runs the app's shutdown (kernel.shutdown())
                try:
                    await asyncio.wait_for(admin_task, timeout=10)
                except (asyncio.TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
                    admin_task.cancel()
            else:
                await kernel.shutdown()


def main(config_path: str, *, admin_port: int | None, admin_host: str = "127.0.0.1") -> int:
    """CLI entry (``quaicu gateway``). Returns a process exit code."""
    logging.basicConfig(
        stream=sys.stderr, level=os.getenv("QUAICU_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        load_gateway_config(config_path)  # validate before starting anything
    except ToolConfigError as exc:
        print(f"Invalid [tools] configuration: {exc}", file=sys.stderr)
        return 2
    try:
        asyncio.run(run_gateway(config_path, admin_port=admin_port, admin_host=admin_host))
    except KeyboardInterrupt:
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0
