"""Compile tool-gateway rules into activated CEL policies, and answer "may the AI see this tool?".

Each concrete tool ``<server>.<tool>`` is governed as the action type ``tool.<server>.<tool>``. For
every rule that covers it, `ToolRuleSet` registers activated `PolicyEnvelope`s in the kernel's
`PolicyStore` — the same trusted path as ``[[policy.seed]]`` — so the ordinary policy engine decides
every call, with its usual conflict resolution (deny > require_approval > allow) and its fail-closed
default (no rule → no policy → DENY).

A rule with ``when_tainted`` compiles to two policies:

- ``<when> && session_tracked && !session_tainted`` → ``decision``
- ``<when> && (!session_tracked || session_tainted)`` → ``when_tainted``

A session whose provenance is not tracked counts as tainted.

Changes (rule added, replaced or removed; a server disabled) recompile everything as a new policy
version and deprecate the old one, so the next call sees the new guardrails.

Pure core (AGENTS.md §1).
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import Any

from quaicu.core.policy.model import PolicyEnvelope, PolicyLifecycle
from quaicu.core.policy.store import PolicyStore
from quaicu.core.toolgate.model import (
    DECISIONS,
    ToolConfigError,
    ToolRule,
    ToolServerSpec,
    check_rule_servers,
)
from quaicu.core.types import ApproverRef, Decision

ACTION_PREFIX = "tool."
EXPOSED_SEPARATOR = "__"
CONFIGURE_ACTION = "kernel.tools.configure"
_TAINTED = "(!session_tracked || session_tainted)"
_CLEAN = "(session_tracked && !session_tainted)"
_RANK = {d: i for i, d in enumerate(DECISIONS)}  # allow < require_approval < deny


def exposed_name(server: str, tool: str) -> str:
    """The name the AI sees: ``<server>__<tool>`` (MCP clients reject dots in tool names)."""
    return f"{server}{EXPOSED_SEPARATOR}{tool}"


def split_exposed(name: str) -> tuple[str, str] | None:
    """``github__get_issue`` → ``("github", "get_issue")``; None if it is not a gateway name.
    Splits on the FIRST separator; server names cannot contain ``_``, so a tool named
    ``other__x`` from server ``evil`` stays ``("evil", "other__x")``."""
    server, sep, tool = name.partition(EXPOSED_SEPARATOR)
    if not sep or not server or not tool:
        return None
    return server, tool


def internal_name(server: str, tool: str) -> str:
    return f"{server}.{tool}"


def action_type(server: str, tool: str) -> str:
    return f"{ACTION_PREFIX}{server}.{tool}"


class ToolRuleSet:
    """The live set of tool rules, compiled into the kernel's policy store."""

    def __init__(
        self,
        rules: Iterable[ToolRule],
        servers: Iterable[ToolServerSpec],
        *,
        store: PolicyStore,
        admin_roles: Iterable[str] = ("role:policy_admin",),
    ) -> None:
        self._store = store
        self._servers = {s.name: s for s in servers}
        self._disabled = {s.name for s in self._servers.values() if not s.enabled}
        self._rules: dict[str, ToolRule] = {}
        for rule in rules:
            check_rule_servers(rule, self._servers)
            self._rules[rule.id] = rule
        self._catalogue: set[str] = set()  # internal names "<server>.<tool>"
        self._registered: list[tuple[str, int]] = []
        self._version = 0
        self._lock = threading.RLock()
        self._register_configure_policy(admin_roles)

    # ── Reads ────────────────────────────────────────────────────────────────

    @property
    def servers(self) -> dict[str, ToolServerSpec]:
        return dict(self._servers)

    @property
    def version(self) -> int:
        return self._version

    def rules(self) -> list[ToolRule]:
        with self._lock:
            return list(self._rules.values())

    def get_rule(self, rule_id: str) -> ToolRule | None:
        with self._lock:
            return self._rules.get(rule_id)

    def server_enabled(self, server: str) -> bool:
        return server in self._servers and server not in self._disabled

    def catalogue(self) -> list[str]:
        with self._lock:
            return sorted(self._catalogue)

    def matching_rules(self, name: str) -> list[ToolRule]:
        with self._lock:
            return [r for r in self._rules.values() if r.matches(name)]

    def effective(self, name: str) -> dict[str, str]:
        """The decision a call would get in a clean and in a tainted session, ignoring ``when``
        guards (a rule with ``when`` is reported as ``"<decision> if <when>"``). "deny" when the
        server is disabled or no rule applies. For the catalogue view; enforcement is the
        policy engine's."""
        server = name.split(".", 1)[0]
        if not self.server_enabled(server):
            return {"clean": "deny", "tainted": "deny"}
        out: dict[str, str] = {}
        for state in ("clean", "tainted"):
            unconditional: list[str] = []
            conditional: list[str] = []
            for rule in self.matching_rules(name):
                decision = rule.when_tainted if state == "tainted" and rule.when_tainted else rule.decision
                (conditional if rule.when else unconditional).append(
                    decision if not rule.when else f"{decision} if {rule.when}"
                )
            if unconditional:
                text = max(unconditional, key=_RANK.__getitem__)
                if conditional and text != "deny":
                    text += " (unless: " + "; ".join(conditional) + ")"
            elif conditional:
                text = "; ".join(conditional) + "; otherwise deny"
            else:
                text = "deny"
            out[state] = text
        return out

    def exposed(self, name: str) -> bool:
        """May the AI see and call ``<server>.<tool>``? False when its server is unknown or
        disabled, when no rule covers it, or when a rule denies it unconditionally in every state.
        Calls to an unexposed tool are refused before the policy engine is even asked."""
        server = name.split(".", 1)[0]
        if not self.server_enabled(server):
            return False
        rules = self.matching_rules(name)
        if not rules:
            return False
        hard_deny = any(
            r.when is None and r.decision == "deny" and r.when_tainted in (None, "deny") for r in rules
        )
        return not hard_deny

    def is_untrusted(self, name: str) -> bool:
        """Does the output of ``<server>.<tool>`` taint the session?"""
        server = self._servers.get(name.split(".", 1)[0])
        if server is not None and server.untrusted_output:
            return True
        return any(r.untrusted_output for r in self.matching_rules(name))

    # ── Changes ──────────────────────────────────────────────────────────────

    def track(self, names: Iterable[str]) -> bool:
        """Add discovered tools (internal names) to the catalogue; recompile if any are new.
        Returns True if the catalogue changed."""
        with self._lock:
            new = {n for n in names if n.split(".", 1)[0] in self._servers} - self._catalogue
            if not new:
                return False
            self._catalogue |= new
            self.apply()
            return True

    def put_rule(self, rule: ToolRule) -> None:
        """Add or replace a rule and recompile."""
        check_rule_servers(rule, self._servers)
        with self._lock:
            self._rules[rule.id] = rule
            self.apply()

    def remove_rule(self, rule_id: str) -> ToolRule:
        with self._lock:
            rule = self._rules.pop(rule_id, None)
            if rule is None:
                raise KeyError(rule_id)
            self.apply()
            return rule

    def set_server_enabled(self, server: str, enabled: bool) -> None:
        if server not in self._servers:
            raise KeyError(server)
        with self._lock:
            if enabled:
                self._disabled.discard(server)
            else:
                self._disabled.add(server)
            self.apply()

    def apply(self) -> None:
        """Recompile every rule for every catalogued tool into a new policy version and retire the
        previous one. New policies are registered before old ones are retired, so no call ever
        sees an empty set it would not otherwise see."""
        with self._lock:
            version = self._version + 1
            envelopes = [
                env
                for name in sorted(self._catalogue)
                if self.server_enabled(name.split(".", 1)[0])
                for env in self._compile(name, version)
            ]
            registered: list[tuple[str, int]] = []
            for env in envelopes:
                self._store.register(env)
                registered.append((env.id, env.version))
            for policy_id, old_version in self._registered:
                self._store.deprecate(policy_id, old_version)
            self._registered = registered
            self._version = version

    # ── Compilation ──────────────────────────────────────────────────────────

    def _compile(self, name: str, version: int) -> list[PolicyEnvelope]:
        server, tool = name.split(".", 1)
        governs = action_type(server, tool)
        out: list[PolicyEnvelope] = []
        for rule in self.matching_rules(name):
            base = f"({rule.when})" if rule.when else "true"
            if rule.when_tainted is None:
                out.append(self._envelope(rule, name, "", governs, base, rule.decision, version))
            else:
                out.append(
                    self._envelope(rule, name, ":clean", governs, f"{base} && {_CLEAN}", rule.decision, version)
                )
                out.append(
                    self._envelope(
                        rule, name, ":tainted", governs, f"{base} && {_TAINTED}", rule.when_tainted, version
                    )
                )
        return out

    @staticmethod
    def _envelope(
        rule: ToolRule, name: str, suffix: str, governs: str, condition: str, decision: str, version: int
    ) -> PolicyEnvelope:
        return PolicyEnvelope(
            id=f"tool:{rule.id}:{name}{suffix}",
            version=version,
            governs=governs,
            scope={"tenant": "*"},
            condition=condition,
            decision=Decision(decision),
            approvers=tuple(ApproverRef(a) for a in rule.approvers) if decision == "require_approval" else (),
            regulatory_refs=(),
            lifecycle=PolicyLifecycle.ACTIVATED,
        )

    def _register_configure_policy(self, admin_roles: Iterable[str]) -> None:
        """Changing the guardrails is itself a governed action (``kernel.tools.configure``): only a
        policy admin may do it, and every change is sealed in the ledger."""
        names: set[str] = set()
        for role in admin_roles:
            bare = role.removeprefix("role:")
            names |= {bare, f"role:{bare}"}
        if not names:
            raise ToolConfigError("no policy-admin roles: nobody could change the tool rules")
        literal = ", ".join(f'"{n}"' for n in sorted(names))
        policy_id = "tool:configure:admins"
        if self._store.get(policy_id, 1) is not None:
            return
        self._store.register(
            PolicyEnvelope(
                id=policy_id,
                version=1,
                governs=CONFIGURE_ACTION,
                scope={"tenant": "*"},
                condition=f"actor_roles.exists(r, r in [{literal}])",
                decision=Decision.ALLOW,
                approvers=(),
                regulatory_refs=(),
                lifecycle=PolicyLifecycle.ACTIVATED,
            )
        )

    # ── Export ───────────────────────────────────────────────────────────────

    def to_toml(self) -> str:
        """The live rules as ``[[tools.rule]]`` entries, to paste back into kernel.toml."""
        lines = [f"# Live tool rules (version {self._version}). Paste into kernel.toml to keep them.", ""]
        for rule in self.rules():
            lines.append("[[tools.rule]]")
            for key, value in rule.as_dict().items():
                lines.append(f"{key} = {_toml_value(value)}")
            lines.append("")
        return "\n".join(lines)


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    text = str(value)
    if "'" not in text and "\n" not in text:
        return f"'{text}'"  # literal string: no escaping, keeps CEL quotes readable
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
