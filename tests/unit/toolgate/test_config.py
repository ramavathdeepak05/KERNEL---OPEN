"""The [tools] section parses strictly: anything ambiguous refuses to start the gateway."""

from __future__ import annotations

import tomllib

import pytest

from quaicu.core.toolgate import ToolConfigError, parse_rule, parse_tools_config
from tests.unit.toolgate.helpers import CONFIG


def _cfg(**overrides) -> dict:
    cfg = tomllib.loads(CONFIG)
    cfg["tools"].update(overrides)
    return cfg


def test_valid_config_parses():
    gw = parse_tools_config(tomllib.loads(CONFIG))
    assert gw.agent_id == "agent:assistant"
    assert [s.name for s in gw.servers] == ["web", "github"]
    assert gw.servers[0].untrusted_output is True
    assert dict(gw.servers[1].env) == {"GITHUB_TOKEN": "ghp-secret"}
    write = next(r for r in gw.rules if r.id == "github-write")
    assert write.when_tainted == "require_approval"
    assert write.approvers == ("role:security",)  # inherited from [tools] approvers, normalised


def _rule(**overrides) -> dict:
    return {"id": "r", "tools": ["github.get_*"], "access": "read", "decision": "allow", **overrides}


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"decision": "maybe"}, "decision"),
        ({"access": "everything"}, "access"),
        ({"when_tainted": "sometimes"}, "when_tainted"),
        ({"tools": []}, "at least one"),
        ({"tools": "github.*"}, "list of strings"),
        ({"tools": ["get_issue"]}, "<server>.<tool>"),
        ({"when": "payload_owner =="}, "invalid CEL"),
        ({"id": "bad id!"}, "id"),
        ({"surprise": 1}, "unknown key"),
        ({"decision": "require_approval"}, "no approvers"),
    ],
)
def test_invalid_rules_are_rejected(overrides, message):
    with pytest.raises(ToolConfigError, match=message):
        parse_rule(_rule(**overrides))


def test_approval_rule_with_explicit_approvers_is_fine():
    rule = parse_rule(_rule(decision="require_approval", approvers=["user:alice", "ops"]))
    assert rule.approvers == ("user:alice", "role:ops")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda t: t["server"].append(dict(t["server"][0])), "unique"),
        (lambda t: t["server"][0].update(name="Bad_Name"), "lowercase"),
        (lambda t: t["server"][0].update(command=[]), "must not be empty"),
        (lambda t: t["server"][1].update(env={"GITHUB_TOKEN": "${GITHUB_TOKEN}"}), "not set"),
        (lambda t: t["server"][1].update(env={"GITHUB_TOKEN": "$GITHUB_TOKEN"}), "not set"),
        (lambda t: t["rule"].append(dict(t["rule"][0])), "unique"),
        (lambda t: t["rule"][0].update(tools=["wbe.fetch"]), "matches no configured server"),
        (lambda t: t.update(server=[]), "at least one"),
        (lambda t: t.update(colour="blue"), "unknown key"),
    ],
)
def test_invalid_configs_are_rejected(mutate, message):
    cfg = tomllib.loads(CONFIG)
    mutate(cfg["tools"])
    with pytest.raises(ToolConfigError, match=message):
        parse_tools_config(cfg)


def test_missing_section_is_rejected():
    with pytest.raises(ToolConfigError, match=r"no \[tools\]"):
        parse_tools_config({})


def test_env_value_with_a_dollar_inside_is_allowed():
    cfg = tomllib.loads(CONFIG)
    cfg["tools"]["server"][1]["env"] = {"PASSWORD": "pa$$word"}
    assert dict(parse_tools_config(cfg).servers[1].env) == {"PASSWORD": "pa$$word"}


def _uncommented_tools_block(path) -> dict:
    """The commented-out [tools] example in a shipped config file, uncommented and parsed."""
    text = path.read_text(encoding="utf-8")
    start = text.index("# [tools]")
    lines = []
    for line in text[start:].splitlines():
        if not line.startswith("#"):
            break
        lines.append(line[2:] if line.startswith("# ") else line[1:])
    return tomllib.loads("\n".join(lines))


@pytest.mark.parametrize("relative", ["kernel.example.toml", "quaicu/templates/kernel.toml"])
def test_documented_examples_parse(relative, monkeypatch):
    from pathlib import Path

    from quaicu.delivery.sdk.kernel import expand_env

    monkeypatch.setenv("GITHUB_TOKEN", "ghp-example")
    root = Path(__file__).resolve().parents[3]
    gw = parse_tools_config(expand_env(_uncommented_tools_block(root / relative)))
    assert gw.servers and gw.rules
