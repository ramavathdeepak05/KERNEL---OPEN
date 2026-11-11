"""Kernel._seed_policies — config-time ACTIVATED policy seeding for the free (STARTER) tier.

Verifies the seeds register as enforcing ACTIVATED policies and that the shipped STARTER seed set
(an allow-baseline + a scoped deny guardrail) governs correctly — crucially that an action WITHOUT
``payload_amount`` is allowed (not fail-closed DENY'd by the guardrail's variable reference).
"""

from __future__ import annotations

import pytest

from quaicu.core.errors import PolicyNotFoundError
from quaicu.core.policy.evaluator import PolicyEngine
from quaicu.core.policy.model import PolicyLifecycle
from quaicu.core.policy.store import PolicyStore
from quaicu.core.types import Action, ActionId, Actor, ActorId, Decision, IdempotencyKey, TenantId
from quaicu.delivery.sdk.kernel import Kernel

# A small seed set: an allow baseline plus one high-value guardrail.
_STARTER_SEEDS = {
    "policy": {
        "seed": [
            {"id": "starter-allow-baseline", "condition": "true", "decision": "allow"},
            {
                "id": "starter-high-value-guardrail",
                "governs": "demo.payment",
                "condition": "payload_amount > 1000000",
                "decision": "deny",
            },
        ]
    }
}


def _action(action_type: str, payload: dict) -> Action:
    return Action(
        id=ActionId("act-1"),
        type=action_type,
        payload=payload,
        actor=Actor(id=ActorId("alice"), tenant=TenantId("acme"), roles=("role:analyst",)),
        tenant=TenantId("acme"),
        idempotency_key=IdempotencyKey("ik-1"),
    )


def _seeded_engine() -> PolicyEngine:
    store = PolicyStore()
    Kernel._seed_policies(store, _STARTER_SEEDS)
    return PolicyEngine(store)


def test_seeds_register_as_activated():
    store = PolicyStore()
    Kernel._seed_policies(store, _STARTER_SEEDS)
    found = store.lookup("demo.payment", "acme")
    ids = {p.id for p in found}
    assert "starter-allow-baseline" in ids and "starter-high-value-guardrail" in ids
    assert all(p.lifecycle is PolicyLifecycle.ACTIVATED for p in found)


def test_no_seeds_is_noop():
    store = PolicyStore()
    Kernel._seed_policies(store, {})  # no [policy.seed] → store stays empty
    assert store.lookup("anything", "acme") == []


async def test_normal_action_is_allowed():
    # An ordinary action with no payload_amount must be ALLOWED by the baseline — the deny guardrail
    # (which references payload_amount) is scoped to demo.payment and must not fail-closed-DENY here.
    engine = _seeded_engine()
    result = await engine.evaluate(_action("widget.create", {"name": "x"}))
    assert result.decision is Decision.ALLOW


async def test_high_value_demo_payment_is_denied():
    engine = _seeded_engine()
    result = await engine.evaluate(_action("demo.payment", {"amount": 5_000_000}))
    assert result.decision is Decision.DENY  # guardrail fires; deny-overrides the baseline allow


async def test_small_demo_payment_is_allowed():
    engine = _seeded_engine()
    result = await engine.evaluate(_action("demo.payment", {"amount": 100}))
    assert result.decision is Decision.ALLOW


async def test_empty_seed_store_fails_closed():
    # Sanity: without the allow-baseline, a CEL engine is fail-closed (proves the baseline matters).
    engine = PolicyEngine(PolicyStore())
    with pytest.raises(PolicyNotFoundError):
        await engine.evaluate(_action("widget.create", {}))
