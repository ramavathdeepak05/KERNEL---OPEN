"""Governed MCP server (D2-1) — exposes registered tools, governed by the kernel.

An operator registers tool handlers (+ an optional per-tool policy) with `GovernedMCPServer`; it serves
them over MCP so an agent's tool calls are each mapped to a governed kernel action (policy → HITL →
seal). DENY / HALT / PENDING block the call (fail-closed); ALLOW executes the handler and returns its
result. The ``mcp`` SDK is imported lazily (``pip install .[mcp]``) so the governance logic stays
importable without it — `handle_call` returns a `CallToolResult` and is unit-testable directly.
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from quaicu.core.provenance import SessionProvenance
from quaicu.core.types import Actor
from quaicu.delivery.mcp.governance import ToolOutcome, ToolStatus, govern_tool_call
from quaicu.delivery.mcp.render import to_call_result
from quaicu.delivery.sdk.kernel import Kernel

if TYPE_CHECKING:
    from quaicu.delivery.mcp.auth import ResolvedSession

log = logging.getLogger("quaicu.mcp.server")

# A registered tool handler: given the call arguments, return the tool result (sync or async).
ToolHandler = Callable[[dict[str, Any]], Any | Awaitable[Any]]


@dataclass
class _RegisteredTool:
    handler: ToolHandler
    policy: str | None  # action type this tool is governed as; None → default mcp.<tool_name>
    description: str
    input_schema: dict[str, Any]
    untrusted: bool = False  # its output may carry injected instructions → taints the session


class GovernedMCPServer:
    """MCP server whose every tool call is governed by the kernel."""

    def __init__(
        self,
        kernel: Kernel | None = None,
        *,
        actor: Actor | None = None,
        name: str = "quaicu-governed",
        default_policy: str | None = None,
        session_resolver: "Callable[[], ResolvedSession] | None" = None,
    ) -> None:
        # Single-tenant: a fixed (kernel, actor) bound at construction (stdio / dedicated).
        # Multi-tenant (hosted HTTP): a `session_resolver` yields the per-request (kernel, actor) from
        # the authenticated caller — bound later by the transport you put in front of it, so the
        # operator can construct a tools-only server and register handlers before auth is wired.
        self._kernel = kernel
        self._actor = actor
        self._name = name
        self._default_policy = default_policy
        self._session_resolver = session_resolver
        self._tools: dict[str, _RegisteredTool] = {}
        # Single-tenant: one server process serves one agent session. In multi-tenant mode the
        # resolved session may carry its own ``provenance``; without one, provenance is untracked.
        self.provenance = SessionProvenance()

    def bind_session_resolver(self, resolver: "Callable[[], ResolvedSession]") -> "GovernedMCPServer":
        """Attach the per-request identity resolver (multi-tenant mode). Returns self for chaining."""
        self._session_resolver = resolver
        return self

    def _resolve_identity(self) -> tuple[Kernel, Actor, SessionProvenance | None]:
        """The (kernel, actor, provenance) this call is governed under — per-request in multi-tenant
        mode.

        In multi-tenant mode this also acts as the auth gate: ``session_resolver`` reads + verifies
        the request's API key and raises (fail-closed) on a missing/invalid key.
        """
        if self._session_resolver is not None:
            session = self._session_resolver()
            return session.kernel, session.actor, getattr(session, "provenance", None)
        if self._kernel is not None and self._actor is not None:
            return self._kernel, self._actor, self.provenance
        raise RuntimeError(
            "GovernedMCPServer has no identity: construct with (kernel, actor) for single-tenant "
            "use, or bind a session_resolver (multi-tenant) before serving."
        )

    def register_tool(
        self,
        name: str,
        handler: ToolHandler,
        *,
        policy: str | None = None,
        description: str = "",
        input_schema: dict[str, Any] | None = None,
        untrusted: bool = False,
    ) -> "GovernedMCPServer":
        """Register a tool. Set ``untrusted=True`` for a tool whose output can carry instructions
        an attacker wrote (it fetches web pages, reads email or files); after it runs, policies see
        ``session_tainted == true`` for the rest of the session."""
        self._tools[name] = _RegisteredTool(
            handler=handler,
            policy=policy or self._default_policy,
            description=description or name,
            input_schema=input_schema or {"type": "object"},
            untrusted=untrusted,
        )
        return self

    # ── Governance (SDK-free, directly testable) ─────────────────────────────────

    async def _govern(self, name: str, arguments: dict[str, Any]) -> ToolOutcome:
        tool = self._tools[name]
        kernel, actor, provenance = self._resolve_identity()

        async def execute(args: dict[str, Any]) -> Any:
            result = tool.handler(args)
            if inspect.isawaitable(result):
                result = await result
            return result

        return await govern_tool_call(
            kernel,
            actor=actor,
            tool_name=name,
            arguments=arguments,
            policy=tool.policy,
            execute=execute,
            provenance=provenance,
            untrusted=tool.untrusted,
        )

    async def handle_call(self, name: str, arguments: dict[str, Any] | None):
        """Govern a tool call and build the `CallToolResult` (import mcp lazily). Testable directly."""
        import mcp.types as types

        if name not in self._tools:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"Unknown tool {name!r}")],
                isError=True,
            )
        return to_call_result(await self._govern(name, dict(arguments or {})))

    # ── MCP transport wiring (lazy import) ───────────────────────────────────────

    def build_mcp_server(self):
        """Wire a low-level ``mcp`` Server bound to this governance."""
        import mcp.types as types
        from mcp.server import Server

        server = Server(self._name)

        @server.list_tools()
        async def _list() -> list:
            # In multi-tenant mode this authenticates the caller (raises on a bad key) so the tool
            # catalogue isn't enumerable without a valid tenant API key. No-op in single-tenant mode.
            self._resolve_identity()
            return [
                types.Tool(name=n, description=t.description, inputSchema=t.input_schema)
                for n, t in self._tools.items()
            ]

        @server.call_tool()
        async def _call(name: str, arguments: dict[str, Any] | None):
            if name not in self._tools:
                raise ValueError(f"Unknown tool {name!r}")
            outcome = await self._govern(name, dict(arguments or {}))
            if outcome.status is ToolStatus.ALLOWED:
                r = outcome.result
                return r if isinstance(r, dict) else [types.TextContent(type="text", text=json.dumps(r, default=str))]
            # Fail-closed: raising marks the CallToolResult isError=True — the tool did not run.
            text = f"{outcome.status.value.lower()} by governance"
            if outcome.status is ToolStatus.PENDING and outcome.handle_id:
                text = f"pending approval: approve handle {outcome.handle_id} via /v1/approvals"
            raise PermissionError(text)

        return server

    async def run_stdio(self) -> None:
        """Serve over stdio (the default MCP transport for a locally-launched server)."""
        from mcp.server.stdio import stdio_server

        server = self.build_mcp_server()
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
