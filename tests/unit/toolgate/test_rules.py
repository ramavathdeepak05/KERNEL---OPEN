"""Rules compile into activated CEL policies that the ordinary policy engine enforces."""

from __future__ import annotations

import tomllib

import pytest

from quaicu.core.errors import PolicyNotFoundError
from quaicu.core.policy import PolicyEngine, PolicyStore
from quaicu.core.policy.model import PolicyLifecycle
from quaicu.core.provenance import SessionProvenance
from quaicu.core.toolgate import (
    ToolConfigError,
    ToolRuleSet,
    exposed_name,
    parse_rule,
    parse_tools_config,
    split_exposed,
)
from quaicu.core.types import Action, ActionId, Actor, ActorId, Decision, IdempotencyKey, TenantId
from tests.unit.toolgate.helpers import CONFIG

TOOLS = ["web.fetch", "github.get_issue", "github.create_issue", "github.delete_repo", "github.transfer_repo"]


def _ruleset() -> tuple[ToolRuleSet, PolicyStore]:
    cfg = parse_tools_config(tomllib.loads(CONFIG))
    store = PolicyStore()
    rules = ToolRuleSet(cfg.rules, cfg.servers, store=store)
    rules.track(TOOLS)
    return rules, store


def _action(name: str, payload: dict, *, tainted: bool | None) -> Action:
    actor = Actor(id=ActorId("agent:a"), tenant=TenantId("local"))
    if tainted is not None:
        prov = SessionProvenance()
        if tainted:
            prov.record("web__fetch")
        actor = prov.stamp(actor)
    return Action(
        id=ActionId("a"), type=f"tool.{name}", payload=payload, actor=actor, tenant=TenantId("local"),
        idempotency_key=IdempotencyKey("k"),
    )


async def _decide(store: PolicyStore, name: str, payload: dict | None = None, *, tainted: bool | None = False):
    return (await PolicyEngine(store).evaluate(_action(name, payload or {}, tainted=tainted))).decision


def test_names_map_between_ai_and_rules():
    assert exposed_name("github", "get_issue") == "github__get_issue"
    assert split_exposed("github__get_issue") == ("github", "get_issue")
    assert split_exposed("evil__github__delete_repo") == ("evil", "github__delete_repo")
    assert split_exposed("plain") is None


async def test_rules_decide_calls():
    _rules, store = _ruleset()
    assert await _decide(store, "github.get_issue") is Decision.ALLOW
    assert await _decide(store, "github.create_issue", {"owner": "acme"}) is Decision.ALLOW
    assert await _decide(store, "github.create_issue", {"owner": "acme"}, tainted=True) is Decision.REQUIRE_APPROVAL
    assert await _decide(store, "github.create_issue", {"owner": "acme"}, tainted=None) is Decision.REQUIRE_APPROVAL
    assert await _decide(store, "github.delete_repo") is Decision.DENY


async def test_uncovered_tool_and_false_guard_are_denied():
    _rules, store = _ruleset()
    with pytest.raises(PolicyNotFoundError):
        await _decide(store, "github.transfer_repo")
    with pytest.raises(PolicyNotFoundError):
        await _decide(store, "github.create_issue", {"owner": "someone-else"})


def test_exposure():
    rules, _ = _ruleset()
    assert rules.exposed("github.get_issue")
    assert rules.exposed("github.create_issue")
    assert not rules.exposed("github.delete_repo")  # unconditional deny → hidden
    assert not rules.exposed("github.transfer_repo")  # no rule → hidden
    assert not rules.exposed("nowhere.tool")  # unknown server


def test_deny_wins_over_a_broader_allow():
    rules, store = _ruleset()
    rules.put_rule(parse_rule({"id": "all", "tools": ["github.*"], "access": "write", "decision": "allow"}))
    assert rules.exposed("github.transfer_repo")
    assert not rules.exposed("github.delete_repo")


async def test_changes_recompile_and_retire_old_versions():
    rules, store = _ruleset()
    before = rules.version
    rules.put_rule(parse_rule({"id": "github-read", "tools": ["github.get_*"], "access": "read", "decision": "deny"}))
    assert rules.version == before + 1
    assert await _decide(store, "github.get_issue") is Decision.DENY
    old = store.get("tool:github-read:github.get_issue", before)
    assert old is not None and old.lifecycle is PolicyLifecycle.DEPRECATED

    rules.remove_rule("github-read")
    with pytest.raises(PolicyNotFoundError):
        await _decide(store, "github.get_issue")


async def test_disabled_server_is_hidden_and_denied():
    rules, store = _ruleset()
    rules.set_server_enabled("github", False)
    assert not rules.exposed("github.get_issue")
    with pytest.raises(PolicyNotFoundError):
        await _decide(store, "github.get_issue")
    rules.set_server_enabled("github", True)
    assert await _decide(store, "github.get_issue") is Decision.ALLOW


def test_rule_for_an_unknown_server_is_refused_live():
    rules, _ = _ruleset()
    with pytest.raises(ToolConfigError):
        rules.put_rule(parse_rule({"id": "x", "tools": ["gitlab.*"], "access": "read", "decision": "allow"}))


def test_untrusted_output_comes_from_server_or_rule():
    rules, _ = _ruleset()
    assert rules.is_untrusted("web.fetch")
    assert not rules.is_untrusted("github.get_issue")
    rules.put_rule(parse_rule({"id": "issues", "tools": ["github.get_issue"], "access": "read",
                               "decision": "allow", "untrusted_output": True}))
    assert rules.is_untrusted("github.get_issue")


def test_effective_view():
    rules, _ = _ruleset()
    assert rules.effective("github.get_issue") == {"clean": "allow", "tainted": "allow"}
    assert rules.effective("github.delete_repo") == {"clean": "deny", "tainted": "deny"}
    eff = rules.effective("github.create_issue")
    assert eff["clean"].startswith("allow if") and eff["tainted"].startswith("require_approval if")


def test_toml_export_round_trips():
    rules, _ = _ruleset()
    exported = tomllib.loads(rules.to_toml())
    reparsed = [parse_rule(r) for r in exported["tools"]["rule"]]
    assert reparsed == rules.rules()


def test_configure_policy_needs_admin_roles():
    cfg = parse_tools_config(tomllib.loads(CONFIG))
    with pytest.raises(ToolConfigError):
        ToolRuleSet(cfg.rules, cfg.servers, store=PolicyStore(), admin_roles=())
