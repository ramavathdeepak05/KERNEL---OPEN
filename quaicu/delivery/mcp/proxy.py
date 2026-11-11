"""Governed MCP proxy (D2-1) — front a downstream MCP server, govern + forward.

`GovernedMCPProxy` sits between the agent and a DOWNSTREAM MCP server (the real tools). It mirrors the
downstream's tool list and governs every call before forwarding it — so the agent AND the downstream
tools need no code change; you just point the agent at the proxy. ALLOW forwards to the downstream;
DENY/HALT/PENDING block the call (fail-closed).

`downstream` is any object exposing ``async list_tools()`` and ``async call_tool(name, arguments)`` (an
``mcp`` ClientSession, or a stub in tests) — so the governance is unit-testable without a live server.
The ``mcp`` server-facing transport is wired lazily.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from quaicu.core.types import Actor
from quaicu.delivery.mcp.governance import ToolOutcome, ToolStatus, govern_tool_call
from quaicu.delivery.mcp.render import to_call_result
from quaicu.delivery.sdk.kernel import Kernel

log = logging.getLogger("quaicu.mcp.proxy")


class Downstream(Protocol):
    async def list_tools(self) -> Any: ...
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any: ...


@dataclass(frozen=True)
class ProxySession:
    """The per-request identity + downstream a hosted (multi-tenant) proxy call is governed under."""

    kernel: Kernel
    actor: Actor
    downstream: Downstream


class GovernedMCPProxy:
    """Govern every tool call, then forward allowed ones to a downstream MCP server.

    Single-tenant (stdio / dedicated): a fixed (kernel, actor, downstream) bound at construction.
    Multi-tenant (hosted HTTP): a `session_resolver` yields the per-request `ProxySession` from the
    authenticated caller — bound later by the transport you put in front of it, so the operator can
    construct a config-only proxy before auth + the per-tenant downstream are wired.
    """

    def __init__(
        self,
        kernel: Kernel | None = None,
        *,
        actor: Actor | None = None,
        downstream: Downstream | None = None,
        name: str = "quaicu-governed-proxy",
        default_policy: str | None = None,
        policy_for: Callable[[str], str | None] | None = None,
        session_resolver: "Callable[[], ProxySession] | None" = None,
    ) -> None:
        self._kernel = kernel
        self._actor = actor
        self._downstream = downstream
        self._name = name
        # The action type each tool is governed as (None → per-tool default mcp.<tool_name>).
        self._policy_for = policy_for or (lambda _name: default_policy)
        self._session_resolver = session_resolver

    def bind_session_resolver(self, resolver: "Callable[[], ProxySession]") -> "GovernedMCPProxy":
        """Attach the per-request identity+downstream resolver (multi-tenant mode). Returns self."""
        self._session_resolver = resolver
        return self

    def _resolve(self) -> ProxySession:
        """The (kernel, actor, downstream) this call is governed under — per-request in multi-tenant
        mode, where the resolver also authenticates (raises fail-closed on a bad key / no downstream)."""
        if self._session_resolver is not None:
            return self._session_resolver()
        if self._kernel is not None and self._actor is not None and self._downstream is not None:
            return ProxySession(self._kernel, self._actor, self._downstream)
        raise RuntimeError(
            "GovernedMCPProxy has no identity/downstream: construct with (kernel, actor, downstream) "
            "for single-tenant use, or bind a session_resolver (multi-tenant) before serving."
        )

    async def _govern(self, name: str, arguments: dict[str, Any]) -> ToolOutcome:
        session = self._resolve()

        async def execute(args: dict[str, Any]) -> Any:
            return await session.downstream.call_tool(name, args)

        return await govern_tool_call(
            session.kernel,
            actor=session.actor,
            tool_name=name,
            arguments=arguments,
            policy=self._policy_for(name),
            execute=execute,
        )

    async def handle_call(self, name: str, arguments: dict[str, Any] | None):
        """Govern a call and build the `CallToolResult` (forwarding to the downstream only on ALLOW)."""
        return to_call_result(await self._govern(name, dict(arguments or {})))

    # ── MCP transport wiring (lazy import) ───────────────────────────────────────

    def build_mcp_server(self):
        """Wire a low-level ``mcp`` Server that mirrors the downstream tools, governed."""
        import mcp.types as types
        from mcp.server import Server

        server = Server(self._name)

        @server.list_tools()
        async def _list() -> list:
            # Multi-tenant: resolves + authenticates the caller, then mirrors THEIR downstream's tools
            # (so each tenant sees only their own tool catalogue). Fixed downstream in single-tenant mode.
            session = self._resolve()
            listed = await session.downstream.list_tools()
            # An mcp ListToolsResult has `.tools`; a plain list is returned as-is.
            return list(getattr(listed, "tools", listed))

        @server.call_tool()
        async def _call(name: str, arguments: dict[str, Any] | None):
            outcome = await self._govern(name, dict(arguments or {}))
            if outcome.status is ToolStatus.ALLOWED:
                r = outcome.result
                # Forward the downstream's own content when it returned an mcp result.
                content = getattr(r, "content", None)
                if content is not None:
                    return content
                return r if isinstance(r, dict) else [types.TextContent(type="text", text=str(r))]
            text = f"{outcome.status.value.lower()} by governance"
            if outcome.status is ToolStatus.PENDING and outcome.handle_id:
                text = f"pending approval: approve handle {outcome.handle_id} via /v1/approvals"
            raise PermissionError(text)

        return server
