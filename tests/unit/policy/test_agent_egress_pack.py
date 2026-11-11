"""Guards the shipped agent-egress starter pack (quaicu/policy_packs/agent-egress/policies.toml):
egress is free from a clean session, reviewed once the session has read untrusted content or is
untracked, and code execution is denied after untrusted input."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from quaicu.core.errors import PolicyNotFoundError
from quaicu.core.policy import packs
from quaicu.core.policy.evaluator import PolicyEngine
from quaicu.core.policy.store import PolicyStore
from quaicu.core.provenance import SessionProvenance
from quaicu.core.types import Action, ActionId, Actor, ActorId, Decision, IdempotencyKey, TenantId
from quaicu.delivery.sdk.kernel import Kernel

_PACK = Path(__file__).resolve().parents[3] / "quaicu" / "policy_packs" / "agent-egress" / "policies.toml"
_AGENT = Actor(id=ActorId("agent:a"), tenant=TenantId("acme"), roles=("agent",))


def _engine() -> PolicyEngine:
    store = PolicyStore()
    Kernel._seed_policies(store, tomllib.loads(_PACK.read_text(encoding="utf-8")))
    return PolicyEngine(store)


def _action(action_type: str, *, sources: tuple[str, ...] | None) -> Action:
    actor = _AGENT
    if sources is not None:
        prov = SessionProvenance()
        for s in sources:
            prov.record(s)
        actor = prov.stamp(actor)
    return Action(
        id=ActionId("a1"), type=action_type, payload={"to": ["bob@example.com"]}, actor=actor,
        tenant=TenantId("acme"), idempotency_key=IdempotencyKey("ik"),
    )


@pytest.mark.parametrize(
    ("action_type", "sources", "expected"),
    [
        ("agent.read", (), Decision.ALLOW),
        ("agent.read", ("fetch",), Decision.ALLOW),
        ("agent.egress", (), Decision.ALLOW),
        ("agent.egress", ("fetch",), Decision.REQUIRE_APPROVAL),
        ("agent.egress", None, Decision.REQUIRE_APPROVAL),
        ("agent.execute", (), Decision.ALLOW),
    ],
)
async def test_decisions(action_type, sources, expected):
    result = await _engine().evaluate(_action(action_type, sources=sources))
    assert result.decision is expected


@pytest.mark.parametrize("sources", [("read_email",), None])
async def test_execute_after_untrusted_input_is_denied(sources):
    result = await _engine().evaluate(_action("agent.execute", sources=sources))
    assert result.decision is Decision.DENY


async def test_unmapped_action_type_is_denied():
    with pytest.raises(PolicyNotFoundError):
        await _engine().evaluate(_action("mcp.unclassified", sources=()))


def test_pack_is_listed_with_metadata():
    pack = packs.get_pack("agent-egress")
    assert pack is not None
    assert set(pack.action_types) == {"agent.read", "agent.egress", "agent.execute"}
    assert len(pack.policies) == 5
