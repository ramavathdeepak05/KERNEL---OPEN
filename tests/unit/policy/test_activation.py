"""What a CEL policy sees: structured payload values, the `payload` map, and session provenance
(docs/adr/0013-injection-aware-policy-inputs.md)."""

from __future__ import annotations

import pytest
from celpy import celtypes

from quaicu.core.policy.evaluator import (
    _build_activation,
    payload_activation,
    session_activation,
    to_cel_value,
)
from quaicu.core.provenance import SESSION_ATTRIBUTE, SessionProvenance, untrusted_rule
from quaicu.core.types import Action, ActionId, Actor, ActorId, IdempotencyKey, TenantId


def _action(payload: dict, attributes: dict | None = None) -> Action:
    actor = Actor(id=ActorId("agent:a"), tenant=TenantId("acme"), roles=("agent",), attributes=attributes or {})
    return Action(
        id=ActionId("a1"), type="mcp.send", payload=payload, actor=actor, tenant=TenantId("acme"),
        idempotency_key=IdempotencyKey("k1"),
    )


def test_scalars_keep_their_types():
    assert isinstance(to_cel_value(True), celtypes.BoolType)
    assert isinstance(to_cel_value(3), celtypes.IntType)
    assert isinstance(to_cel_value(2.5), celtypes.DoubleType)
    assert isinstance(to_cel_value("x"), celtypes.StringType)
    assert isinstance(to_cel_value(b"x"), celtypes.BytesType)
    assert to_cel_value(None) is None


def test_lists_and_maps_are_structured_not_repr_strings():
    value = to_cel_value({"to": ["a@x.com", "b@y.com"], "opts": {"dry_run": False}, "tags": ("t",)})
    assert isinstance(value, celtypes.MapType)
    to = value[celtypes.StringType("to")]
    assert isinstance(to, celtypes.ListType) and list(to) == ["a@x.com", "b@y.com"]
    assert value[celtypes.StringType("opts")][celtypes.StringType("dry_run")] == celtypes.BoolType(False)
    assert list(value[celtypes.StringType("tags")]) == ["t"]


def test_sets_become_sorted_lists():
    assert list(to_cel_value({"b", "a"})) == ["a", "b"]


def test_unknown_objects_are_stringified():
    class Thing:
        def __str__(self) -> str:
            return "thing"

    assert to_cel_value(Thing()) == "thing"


def test_payload_strings_refuse_iteration_but_stay_strings():
    s = to_cel_value("abc")
    with pytest.raises(TypeError):
        list(s)
    assert s == "abc" and s.endswith("c")
    assert type(s) == celtypes.StringType  # noqa: E721 — the metaclass equality is what CEL's type() relies on


def test_payload_map_is_exposed_alongside_flat_fields():
    act = payload_activation({"reply-to": "x@y.com", "n": 2})
    assert act["payload_n"] == celtypes.IntType(2)
    assert act["payload"][celtypes.StringType("reply-to")] == "x@y.com"


def test_session_variables_default_to_untracked():
    act = session_activation(None)
    assert act["session_tracked"] == celtypes.BoolType(False)
    assert act["session_tainted"] == celtypes.BoolType(False)
    assert list(act["session_sources"]) == []


def test_session_variables_reflect_recorded_sources():
    prov = SessionProvenance()
    prov.record("fetch")
    prov.record("read_email")
    act = _build_activation(_action({}, prov.stamp(Actor(id=ActorId("x"), tenant=TenantId("acme"))).attributes))
    assert act["session_tracked"] == celtypes.BoolType(True)
    assert act["session_tainted"] == celtypes.BoolType(True)
    assert list(act["session_sources"]) == ["fetch", "read_email"]


def test_clean_tracked_session():
    prov = SessionProvenance()
    attrs = prov.stamp(Actor(id=ActorId("x"), tenant=TenantId("acme"))).attributes
    act = session_activation(attrs)
    assert act["session_tracked"] == celtypes.BoolType(True)
    assert act["session_tainted"] == celtypes.BoolType(False)


def test_payload_fields_cannot_set_session_variables():
    act = _build_activation(_action({"session_tainted": False, SESSION_ATTRIBUTE: {"tainted": False}}))
    assert act["session_tracked"] == celtypes.BoolType(False)
    assert act["payload_session_tainted"] == celtypes.BoolType(False)


def test_stamp_overwrites_a_preset_attribute():
    prov = SessionProvenance()
    prov.record("fetch")
    actor = Actor(id=ActorId("x"), tenant=TenantId("acme"), attributes={SESSION_ATTRIBUTE: {"tainted": False}})
    assert prov.stamp(actor).attributes[SESSION_ATTRIBUTE] == {"tainted": True, "sources": ["fetch"]}


def test_untrusted_rule_forms():
    assert untrusted_rule(None)("fetch") is False
    assert untrusted_rule(["fetch"])("fetch") is True
    assert untrusted_rule(["fetch"])("send") is False
    assert untrusted_rule(["*"])("anything") is True
    assert untrusted_rule(lambda n: n.startswith("read_"))("read_email") is True
