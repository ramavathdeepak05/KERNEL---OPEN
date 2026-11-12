"""Governed MCP proxy (D2-1) — front a downstream MCP server, govern + forward.

`GovernedMCPProxy` sits between the agent and a DOWNSTREAM MCP server (the real tools). It mirrors the
downstream's tool list and governs every call before forwarding it — so the agent AND the downstream
tools need no code change; you just point the agent at the proxy. ALLOW forwards to the downstream;
DENY/HALT/PENDING block the call (fail-closed).

Prompt-injection controls (docs/adr/0013-injection-aware-policy-inputs.md):

- ``untrusted_tools``: tools whose output may carry injected instructions (web fetch, email or file
  readers). Once one has run, the session is tainted and policies see ``session_tainted`` — e.g. to
  hold egress tools for approval.
- ``allowed_tools``: when set, only these downstream tools are listed or callable.
- ``pin_tool_descriptions`` (default on): the first listing pins each tool's name, description and
  input schema. A tool whose definition later changes (a "rug pull" or poisoned description) is
  dropped from the listing and its calls are denied, until the proxy is restarted.

`downstream` is any object exposing ``async list_tools()`` and ``async call_tool(name, arguments)`` (an
``mcp`` ClientSession, or a stub in tests) — so the governance is unit-testable without a live server.
The ``mcp`` server-facing transport is wired lazily.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from quaicu.core.provenance import SessionProvenance, TrustRule, untrusted_rule
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
    # This caller's session taint state. None → provenance is not tracked for the session (policies
    # see session_tracked == false).
    provenance: SessionProvenance | None = None


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
        untrusted_tools: Iterable[str] | TrustRule | None = None,
        allowed_tools: Iterable[str] | None = None,
        pin_tool_descriptions: bool = True,
        expose: Callable[[str], bool] | None = None,
    ) -> None:
        self._kernel = kernel
        self._actor = actor
        self._downstream = downstream
        self._name = name
        # The action type each tool is governed as (None → per-tool default mcp.<tool_name>).
        self._policy_for = policy_for or (lambda _name: default_policy)
        self._session_resolver = session_resolver
        self._is_untrusted = untrusted_rule(untrusted_tools)
        self._allowed = frozenset(allowed_tools) if allowed_tools is not None else None
        self._pin = pin_tool_descriptions
        # A dynamic allowlist (e.g. the tool gateway's rules): a tool it rejects is neither listed
        # nor callable. Checked on every listing and call, so a live rule change applies at once.
        self._expose = expose
        # The MCP session of the connected agent, captured on its first request, so the proxy can
        # tell it the tool list changed (best-effort; calls are enforced either way).
        self.mcp_session: Any = None
        # Single-tenant: one proxy process serves one agent session.
        self.provenance = SessionProvenance()
        # (tenant, tool name) → fingerprint of the definition first listed; and those that changed.
        self._pins: dict[tuple[str, str], str] = {}
        self._drifted: set[tuple[str, str]] = set()

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
            return ProxySession(self._kernel, self._actor, self._downstream, self.provenance)
        raise RuntimeError(
            "GovernedMCPProxy has no identity/downstream: construct with (kernel, actor, downstream) "
            "for single-tenant use, or bind a session_resolver (multi-tenant) before serving."
        )

    # ── Tool catalogue controls ──────────────────────────────────────────────────

    @staticmethod
    def _definition_fingerprint(tool: Any) -> str:
        """Hash of what the agent is told about a tool: its name, description and input schema."""
        def field(key: str) -> Any:
            return tool.get(key) if isinstance(tool, dict) else getattr(tool, key, None)

        definition = {
            "name": field("name"),
            "description": field("description"),
            "input_schema": field("inputSchema") or field("input_schema"),
        }
        canonical = json.dumps(definition, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def filter_tools(self, session: ProxySession, tools: Iterable[Any]) -> list[Any]:
        """Apply ``allowed_tools`` and description pinning to a downstream listing."""
        tenant = str(session.kernel.tenant)
        kept: list[Any] = []
        for tool in tools:
            name = tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", None)
            name = str(name)
            if self._allowed is not None and name not in self._allowed:
                continue
            if self._expose is not None and not self._expose(name):
                continue
            if self._pin:
                key = (tenant, name)
                fingerprint = self._definition_fingerprint(tool)
                pinned = self._pins.setdefault(key, fingerprint)
                if pinned != fingerprint or key in self._drifted:
                    if key not in self._drifted:
                        log.warning(
                            "MCP tool %r changed its definition since it was first listed; "
                            "hiding it and denying its calls (tenant %s)", name, tenant,
                        )
                    self._drifted.add(key)
                    continue
            kept.append(tool)
        return kept

    def _blocked_reason(self, session: ProxySession, name: str) -> str | None:
        if self._allowed is not None and name not in self._allowed:
            return f"tool {name!r} is not in the proxy's allowed_tools"
        if self._expose is not None and not self._expose(name):
            return f"tool {name!r} is not available through this gateway"
        if (str(session.kernel.tenant), name) in self._drifted:
            return f"tool {name!r} changed its definition since it was first listed"
        return None

    async def _govern(self, name: str, arguments: dict[str, Any]) -> ToolOutcome:
        session = self._resolve()
        blocked = self._blocked_reason(session, name)
        if blocked is not None:
            log.warning("MCP proxy blocked a call before governance: %s", blocked)
            return ToolOutcome(ToolStatus.DENIED, reason=blocked)

        async def execute(args: dict[str, Any]) -> Any:
            return await session.downstream.call_tool(name, args)

        return await govern_tool_call(
            session.kernel,
            actor=session.actor,
            tool_name=name,
            arguments=arguments,
            policy=self._policy_for(name),
            execute=execute,
            provenance=session.provenance,
            untrusted=self._is_untrusted(name),
        )

    async def notify_tools_changed(self) -> bool:
        """Tell the connected agent to re-list its tools. Returns False when no agent is connected
        or the notification could not be sent."""
        session = self.mcp_session
        if session is None:
            return False
        try:
            await session.send_tool_list_changed()
        except Exception:  # noqa: BLE001 — best-effort; enforcement does not depend on it
            log.debug("could not send tools/list_changed", exc_info=True)
            return False
        return True

    def _capture_session(self, server: Any) -> None:
        try:
            self.mcp_session = server.request_context.session
        except (LookupError, AttributeError):
            pass

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
            self._capture_session(server)
            session = self._resolve()
            listed = await session.downstream.list_tools()
            # An mcp ListToolsResult has `.tools`; a plain list is returned as-is.
            return self.filter_tools(session, getattr(listed, "tools", listed))

        @server.call_tool()
        async def _call(name: str, arguments: dict[str, Any] | None):
            self._capture_session(server)
            outcome = await self._govern(name, dict(arguments or {}))
            if outcome.status is ToolStatus.ALLOWED:
                r = outcome.result
                # Forward the downstream's own result when it returned an mcp result: its content,
                # its structured content (a tool with an outputSchema fails validation without it,
                # so the agent would be told a call failed that in fact ran), and its error flag.
                content = getattr(r, "content", None)
                if content is not None:
                    if getattr(r, "isError", False):
                        texts = " ".join(getattr(c, "text", "") for c in content).strip()
                        raise RuntimeError(texts or "downstream tool returned an error")
                    structured = getattr(r, "structuredContent", None)
                    return (content, structured) if structured is not None else content
                return r if isinstance(r, dict) else [types.TextContent(type="text", text=str(r))]
            text = f"{outcome.status.value.lower()} by governance"
            if outcome.status is ToolStatus.PENDING and outcome.handle_id:
                text = f"pending approval: approve handle {outcome.handle_id} via /v1/approvals"
            raise PermissionError(text)

        return server
