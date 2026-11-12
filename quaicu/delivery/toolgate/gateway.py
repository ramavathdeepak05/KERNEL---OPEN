"""The tool gateway: one governed MCP endpoint in front of every tool server the AI may use.

The AI connects only to the gateway. The gateway starts the configured MCP servers itself, with
their credentials, and shows the AI their tools as ``<server>__<tool>``. Every call is a governed
action of type ``tool.<server>.<tool>``: the rules in ``[tools]`` (compiled by
`quaicu.core.toolgate.ToolRuleSet`) decide it, a human approves it when a rule says so, and the
ledger records it. A tool no rule covers is not listed and cannot be called.

What the AI never gets: the servers' credentials, any way to approve, and any way to change the
rules. Those are for people, through the admin API (``/v1/tools``, ``/v1/approvals``).

Built on `GovernedMCPProxy`, so it inherits session taint, tool-definition pinning,
approve-then-retry and structured-output forwarding.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Mapping
from typing import Any

from quaicu.core.toolgate import (
    CONFIGURE_ACTION,
    ToolGatewayConfig,
    ToolRule,
    ToolRuleSet,
    action_type,
    exposed_name,
    internal_name,
    split_exposed,
)
from quaicu.core.types import Actor, ActorId
from quaicu.delivery.mcp.proxy import Downstream, GovernedMCPProxy
from quaicu.delivery.sdk.kernel import Kernel

log = logging.getLogger("quaicu.toolgate")


def _tool_name(tool: Any) -> str:
    return str(tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", ""))


def _renamed(tool: Any, name: str) -> Any:
    if isinstance(tool, dict):
        return {**tool, "name": name}
    copy = getattr(tool, "model_copy", None)
    if copy is not None:
        return copy(update={"name": name})
    raise TypeError(f"unsupported tool listing entry: {tool!r}")


class MultiDownstream:
    """Several MCP client sessions presented as one `Downstream`, tools prefixed by server name."""

    def __init__(
        self,
        sessions: Mapping[str, Downstream],
        *,
        on_listed: Callable[[list[str]], None] | None = None,
    ) -> None:
        self._sessions = dict(sessions)
        self._on_listed = on_listed

    async def list_tools(self) -> list[Any]:
        tools: list[Any] = []
        internal: list[str] = []
        for server, session in self._sessions.items():
            try:
                listed = await session.list_tools()
            except Exception:  # noqa: BLE001 — one broken server must not hide every other tool
                log.exception("tool server %r failed to list its tools; its tools are unavailable", server)
                continue
            for tool in getattr(listed, "tools", listed):
                name = _tool_name(tool)
                if not name:
                    continue
                tools.append(_renamed(tool, exposed_name(server, name)))
                internal.append(internal_name(server, name))
        if self._on_listed is not None:
            self._on_listed(internal)
        return tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        parts = split_exposed(name)
        if parts is None or parts[0] not in self._sessions:
            raise LookupError(f"no tool server for {name!r}")
        server, tool = parts
        return await self._sessions[server].call_tool(tool, arguments)


class ToolGateway:
    """Governs every tool call the AI makes, across all configured tool servers."""

    def __init__(
        self,
        kernel: Kernel,
        config: ToolGatewayConfig,
        sessions: Mapping[str, Downstream],
    ) -> None:
        if kernel.policy_store is None:
            raise ValueError(
                'The tool gateway compiles its rules into CEL policies: set [adapters].policy = "cel_policy".'
            )
        missing = {s.name for s in config.servers} - set(sessions)
        if missing:
            raise ValueError(f"no session for tool server(s) {sorted(missing)}")
        self.kernel = kernel
        self.config = config
        self.rules = ToolRuleSet(
            config.rules,
            config.servers,
            store=kernel.policy_store,
            admin_roles=kernel.policy_admin_roles,
        )
        self.actor = Actor(
            id=ActorId(config.agent_id), tenant=kernel.tenant, roles=tuple(config.agent_roles)
        )
        self.downstream = MultiDownstream(sessions, on_listed=self.rules.track)
        self.proxy = GovernedMCPProxy(
            kernel,
            actor=self.actor,
            downstream=self.downstream,
            name="quaicu-tool-gateway",
            policy_for=self._policy_for,
            untrusted_tools=self._untrusted,
            expose=self._exposed,
            pin_tool_descriptions=True,
        )
        kernel.toolgate = self

    # ── Name mapping (exposed "server__tool" → internal "server.tool") ─────────

    def _internal(self, exposed: str) -> str | None:
        parts = split_exposed(exposed)
        if parts is None or parts[0] not in self.rules.servers:
            return None
        return internal_name(*parts)

    def _exposed(self, exposed: str) -> bool:
        name = self._internal(exposed)
        if name is None:
            return False
        # A call can arrive before any listing (or for a tool the server added since): make sure
        # its rules are compiled before the policy engine is asked.
        self.rules.track([name])
        return self.rules.exposed(name)

    def _policy_for(self, exposed: str) -> str:
        parts = split_exposed(exposed)
        if parts is None:
            return "tool.unknown"  # never governed by a rule → fail-closed deny
        return action_type(*parts)

    def _untrusted(self, exposed: str) -> bool:
        name = self._internal(exposed)
        return name is not None and self.rules.is_untrusted(name)

    # ── MCP serving ──────────────────────────────────────────────────────────

    def build_mcp_server(self):
        return self.proxy.build_mcp_server()

    async def handle_call(self, exposed: str, arguments: dict[str, Any] | None):
        """Govern one call by its exposed name (for tests and embedding)."""
        return await self.proxy.handle_call(exposed, arguments)

    async def list_tools(self) -> list[Any]:
        """What the AI sees: the tools the rules expose (for tests and the catalogue)."""
        session = self.proxy._resolve()
        return self.proxy.filter_tools(session, await self.downstream.list_tools())

    # ── Administration (called by the admin API, always as a person) ───────────

    async def configure(self, actor: Actor, op: str, payload: dict[str, Any], change: Callable[[], Any]) -> Any:
        """Apply a guardrail change as a governed action: allowed only for a policy admin, sealed
        in the ledger with who changed what. Raises the kernel's lifecycle errors on DENY/HALT."""
        result = await self.kernel.govern_action(
            action_type=CONFIGURE_ACTION,
            actor=actor,
            payload={"op": op, **payload},
            execute=change,
        )
        self._announce_change()
        return result

    async def put_rule(self, actor: Actor, rule: ToolRule) -> ToolRule:
        await self.configure(actor, "put_rule", {"rule": rule.as_dict()}, lambda: self.rules.put_rule(rule))
        return rule

    async def remove_rule(self, actor: Actor, rule_id: str) -> None:
        await self.configure(actor, "remove_rule", {"rule_id": rule_id}, lambda: self.rules.remove_rule(rule_id))

    async def set_server_enabled(self, actor: Actor, server: str, enabled: bool) -> None:
        await self.configure(
            actor,
            "enable_server" if enabled else "disable_server",
            {"server": server},
            lambda: self.rules.set_server_enabled(server, enabled),
        )

    async def reset_session(self, actor: Actor) -> None:
        await self.configure(actor, "reset_session", {}, self.proxy.provenance.reset)

    def _announce_change(self) -> None:
        try:
            asyncio.get_running_loop().create_task(self.proxy.notify_tools_changed())
        except RuntimeError:
            pass

    def catalogue(self) -> dict[str, Any]:
        """The servers, every tool seen so far with its effective decisions, and the session."""
        drifted = {name for (_tenant, name) in self.proxy._drifted}
        tools = []
        for name in self.rules.catalogue():
            server, tool = name.split(".", 1)
            rules = self.rules.matching_rules(name)
            tools.append(
                {
                    "name": name,
                    "exposed_as": exposed_name(server, tool),
                    "server": server,
                    "visible": self.rules.exposed(name) and exposed_name(server, tool) not in drifted,
                    "definition_changed": exposed_name(server, tool) in drifted,
                    "access": sorted({r.access for r in rules}),
                    "rules": [r.id for r in rules],
                    "decision": self.rules.effective(name),
                    "untrusted_output": self.rules.is_untrusted(name),
                }
            )
        return {
            "agent": {"id": str(self.actor.id), "roles": list(self.actor.roles)},
            "rules_version": self.rules.version,
            "servers": [
                {
                    "name": s.name,
                    "enabled": self.rules.server_enabled(s.name),
                    "untrusted_output": s.untrusted_output,
                    "description": s.description,
                }
                for s in self.rules.servers.values()
            ],
            "tools": tools,
            "session": {
                "tainted": self.proxy.provenance.tainted,
                "sources": list(self.proxy.provenance.sources),
            },
        }
