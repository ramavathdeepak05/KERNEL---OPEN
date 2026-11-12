"""Tool-gateway configuration: the tool servers the gateway fronts and the rules that govern them.

Read from the ``[tools]`` section of kernel.toml (and accepted in the same shape by the live admin
API). Parsing is strict: anything ambiguous raises `ToolConfigError`, and the gateway refuses to
start — a guardrail that does not say what it means is not a guardrail.

    [tools]
    agent_id    = "agent:assistant"
    agent_roles = ["agent"]
    approvers   = ["role:security"]

    [[tools.server]]
    name    = "github"
    command = ["npx", "-y", "@modelcontextprotocol/server-github"]
    env     = { GITHUB_TOKEN = "${GITHUB_TOKEN}" }
    untrusted_output = true

    [[tools.rule]]
    id           = "github-write"
    tools        = ["github.create_*", "github.update_*"]
    access       = "write"
    decision     = "allow"
    when_tainted = "require_approval"
    when         = 'payload_owner == "acme"'

Pure core: standard library plus the CEL compiler (AGENTS.md §1).
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

DECISIONS = ("allow", "require_approval", "deny")
ACCESS = ("read", "write", "egress", "execute", "admin")

# Server names may not contain "_" so that "<server>__<tool>" always splits unambiguously.
_SERVER_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
# What os.path.expandvars leaves behind when a variable is unset.
_BARE_VAR = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$")
_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_SERVER_NAME = 32

_RULE_KEYS = {
    "id", "tools", "access", "decision", "when_tainted", "when", "approvers", "untrusted_output",
    "description",
}
_SERVER_KEYS = {"name", "command", "env", "untrusted_output", "enabled", "description"}
_TOOLS_KEYS = {"agent_id", "agent_roles", "approvers", "server", "rule"}


class ToolConfigError(ValueError):
    """The tool-gateway configuration is invalid. The gateway does not start (fail-closed)."""


@dataclass(frozen=True)
class ToolServerSpec:
    """One downstream MCP server the gateway starts and fronts."""

    name: str
    command: tuple[str, ...]
    env: Mapping[str, str] = field(default_factory=dict)
    untrusted_output: bool = False
    enabled: bool = True
    description: str = ""


@dataclass(frozen=True)
class ToolRule:
    """Which tools a rule covers and what they may do.

    ``tools`` are globs over ``<server>.<tool>``. ``decision`` applies to a clean session; when
    ``when_tainted`` is set it replaces ``decision`` once the session has read untrusted output (or
    when provenance is not tracked). ``when`` is an optional CEL guard: where it is false, the rule
    does not apply.
    """

    id: str
    tools: tuple[str, ...]
    access: str
    decision: str
    when_tainted: str | None = None
    when: str | None = None
    approvers: tuple[str, ...] = ()
    untrusted_output: bool = False
    description: str = ""

    def matches(self, name: str) -> bool:
        """True if this rule covers the tool ``<server>.<tool>``."""
        return any(fnmatch.fnmatchcase(name, pattern) for pattern in self.tools)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "tools": list(self.tools),
            "access": self.access,
            "decision": self.decision,
        }
        if self.when_tainted is not None:
            out["when_tainted"] = self.when_tainted
        if self.when is not None:
            out["when"] = self.when
        if self.approvers:
            out["approvers"] = list(self.approvers)
        if self.untrusted_output:
            out["untrusted_output"] = True
        if self.description:
            out["description"] = self.description
        return out


@dataclass(frozen=True)
class ToolGatewayConfig:
    agent_id: str
    agent_roles: tuple[str, ...]
    approvers: tuple[str, ...]
    servers: tuple[ToolServerSpec, ...]
    rules: tuple[ToolRule, ...]


# ── Parsing ──────────────────────────────────────────────────────────────────


def _unknown_keys(raw: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ToolConfigError(f"{where}: unknown key(s) {unknown}; allowed: {sorted(allowed)}")


def _str_list(value: Any, where: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise ToolConfigError(f"{where} must be a list of strings")
    items = tuple(value)
    if not all(isinstance(v, str) and v.strip() for v in items):
        raise ToolConfigError(f"{where} must be a list of non-empty strings")
    return tuple(v.strip() for v in items)


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ToolConfigError(f"{where} must be true or false")
    return value


def _choice(value: Any, choices: tuple[str, ...], where: str) -> str:
    if not isinstance(value, str) or value.lower() not in choices:
        raise ToolConfigError(f"{where} must be one of {list(choices)}, got {value!r}")
    return value.lower()


def _normalize_ref(ref: str) -> str:
    """Approver refs are ``role:<name>`` or ``user:<id>``; a bare name is a role."""
    return ref if ref.startswith(("role:", "user:")) else f"role:{ref}"


def _check_cel(condition: str, where: str) -> None:
    import celpy

    try:
        celpy.Environment().compile(condition)
    except Exception as exc:  # noqa: BLE001 — any compile failure is a config error
        raise ToolConfigError(f"{where}: invalid CEL {condition!r}: {exc}") from exc


def parse_server(raw: Mapping[str, Any]) -> ToolServerSpec:
    if not isinstance(raw, Mapping):
        raise ToolConfigError("[[tools.server]] entries must be tables")
    _unknown_keys(raw, _SERVER_KEYS, "[[tools.server]]")
    name = raw.get("name")
    if not isinstance(name, str) or not _SERVER_NAME.match(name) or len(name) > _MAX_SERVER_NAME:
        raise ToolConfigError(
            f"[[tools.server]] name {name!r} must be lowercase letters, digits and single hyphens "
            f"(at most {_MAX_SERVER_NAME} characters)"
        )
    where = f"[[tools.server]] {name!r}"
    command = _str_list(raw.get("command"), f"{where} command")
    if not command:
        raise ToolConfigError(f"{where} command must not be empty")
    env_raw = raw.get("env", {})
    if not isinstance(env_raw, Mapping):
        raise ToolConfigError(f"{where} env must be a table of strings")
    env: dict[str, str] = {}
    for key, value in env_raw.items():
        if not isinstance(value, str):
            raise ToolConfigError(f"{where} env.{key} must be a string")
        if "${" in value or _BARE_VAR.match(value):
            raise ToolConfigError(
                f"{where} env.{key} refers to an environment variable that is not set ({value})"
            )
        env[str(key)] = value
    return ToolServerSpec(
        name=name,
        command=command,
        env=env,
        untrusted_output=_bool(raw.get("untrusted_output", False), f"{where} untrusted_output"),
        enabled=_bool(raw.get("enabled", True), f"{where} enabled"),
        description=str(raw.get("description", "")),
    )


def parse_rule(raw: Mapping[str, Any], *, default_approvers: tuple[str, ...] = ()) -> ToolRule:
    """Parse and validate one rule (from kernel.toml or the admin API)."""
    if not isinstance(raw, Mapping):
        raise ToolConfigError("a tool rule must be a table/object")
    _unknown_keys(raw, _RULE_KEYS, "tool rule")
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not _RULE_ID.match(rule_id):
        raise ToolConfigError(
            f"tool rule id {rule_id!r} must start with a letter or digit and use only letters, "
            "digits, '.', '_' and '-' (at most 64 characters)"
        )
    where = f"tool rule {rule_id!r}"
    tools = _str_list(raw.get("tools"), f"{where} tools")
    if not tools:
        raise ToolConfigError(f"{where} tools must name at least one tool")
    for pattern in tools:
        if "." not in pattern:
            raise ToolConfigError(
                f"{where}: tool pattern {pattern!r} must be '<server>.<tool>' (globs allowed, "
                "e.g. 'github.get_*' or 'github.*')"
            )
    access = _choice(raw.get("access"), ACCESS, f"{where} access")
    decision = _choice(raw.get("decision"), DECISIONS, f"{where} decision")
    when_tainted = raw.get("when_tainted")
    if when_tainted is not None:
        when_tainted = _choice(when_tainted, DECISIONS, f"{where} when_tainted")
    when = raw.get("when")
    if when is not None:
        if not isinstance(when, str) or not when.strip():
            raise ToolConfigError(f"{where} when must be a non-empty CEL expression")
        when = when.strip()
        _check_cel(when, f"{where} when")
    approvers = tuple(
        _normalize_ref(a) for a in _str_list(raw.get("approvers", ()), f"{where} approvers")
    ) or tuple(_normalize_ref(a) for a in default_approvers)
    if "require_approval" in (decision, when_tainted) and not approvers:
        raise ToolConfigError(
            f"{where} can require approval but names no approvers (set approvers here or in [tools])"
        )
    return ToolRule(
        id=rule_id,
        tools=tools,
        access=access,
        decision=decision,
        when_tainted=when_tainted,
        when=when,
        approvers=approvers,
        untrusted_output=_bool(raw.get("untrusted_output", False), f"{where} untrusted_output"),
        description=str(raw.get("description", "")),
    )


def parse_tools_config(cfg: Mapping[str, Any]) -> ToolGatewayConfig:
    """Parse the whole kernel config's ``[tools]`` section. Raises `ToolConfigError`."""
    tools = cfg.get("tools")
    if not isinstance(tools, Mapping):
        raise ToolConfigError("the kernel config has no [tools] section")
    _unknown_keys(tools, _TOOLS_KEYS, "[tools]")
    agent_id = tools.get("agent_id", "agent:assistant")
    if not isinstance(agent_id, str) or not agent_id.strip():
        raise ToolConfigError("[tools] agent_id must be a non-empty string")
    agent_roles = _str_list(tools.get("agent_roles", ()), "[tools] agent_roles")
    approvers = tuple(_normalize_ref(a) for a in _str_list(tools.get("approvers", ()), "[tools] approvers"))

    servers = tuple(parse_server(s) for s in tools.get("server", ()))
    if not servers:
        raise ToolConfigError("[tools] needs at least one [[tools.server]]")
    names = [s.name for s in servers]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ToolConfigError(f"[[tools.server]] names must be unique; duplicated: {duplicates}")

    rules = tuple(parse_rule(r, default_approvers=approvers) for r in tools.get("rule", ()))
    ids = [r.id for r in rules]
    dup_rules = sorted({i for i in ids if ids.count(i) > 1})
    if dup_rules:
        raise ToolConfigError(f"[[tools.rule]] ids must be unique; duplicated: {dup_rules}")
    for rule in rules:
        check_rule_servers(rule, names)
    return ToolGatewayConfig(
        agent_id=agent_id.strip(),
        agent_roles=agent_roles,
        approvers=approvers,
        servers=servers,
        rules=rules,
    )


def check_rule_servers(rule: ToolRule, server_names: Iterable[str]) -> None:
    """Every pattern in a rule must be able to match at least one configured server — a typo in a
    server name would otherwise leave a rule silently doing nothing."""
    names = list(server_names)
    for pattern in rule.tools:
        server_part = pattern.split(".", 1)[0]
        if not any(fnmatch.fnmatchcase(n, server_part) for n in names):
            raise ToolConfigError(
                f"tool rule {rule.id!r}: pattern {pattern!r} matches no configured server "
                f"(servers: {names})"
            )
