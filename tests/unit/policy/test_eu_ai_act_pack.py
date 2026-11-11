"""Guards the shipped EU AI Act starter policy pack (quaicu/policy_packs/eu-ai-act/policies.toml).

Loads the pack, seeds it into a PolicyStore (which compiles the CEL — so this catches a broken
expression), and asserts the documented compliance behavior end-to-end.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from quaicu.core.policy.evaluator import PolicyEngine
from quaicu.core.policy.store import PolicyStore
from quaicu.core.types import Action, ActionId, Actor, ActorId, Decision, IdempotencyKey, TenantId
from quaicu.delivery.sdk.kernel import Kernel

_PACK = Path(__file__).resolve().parents[3] / "quaicu" / "policy_packs" / "eu-ai-act" / "policies.toml"


def _engine() -> PolicyEngine:
    cfg = tomllib.loads(_PACK.read_text(encoding="utf-8"))
    store = PolicyStore()
    Kernel._seed_policies(store, cfg)  # compiles every CEL condition
    return PolicyEngine(store)


def _action(action_type: str, payload: dict) -> Action:
    return Action(
        id=ActionId("a1"),
        type=action_type,
        payload=payload,
        actor=Actor(id=ActorId("svc"), tenant=TenantId("acme"), roles=("role:operator",)),
        tenant=TenantId("acme"),
        idempotency_key=IdempotencyKey("ik-1"),
    )


# A fully-classified, compliant invocation: limited-risk, permitted use, oversight present, AI disclosed.
_COMPLIANT = {
    "risk_category": "limited",
    "use_case": "customer_support",
    "human_oversight": True,
    "discloses_ai": True,
}


async def test_pack_compiles_and_seeds():
    engine = _engine()  # raises if any CEL is invalid
    assert engine._store.lookup("ai_system.invoke", "acme")  # policies present


async def test_compliant_invocation_allowed():
    result = await _engine().evaluate(_action("ai_system.invoke", _COMPLIANT))
    assert result.decision is Decision.ALLOW


async def test_prohibited_risk_denied():
    result = await _engine().evaluate(
        _action("ai_system.invoke", {**_COMPLIANT, "risk_category": "prohibited"})
    )
    assert result.decision is Decision.DENY


async def test_banned_use_case_denied():
    result = await _engine().evaluate(
        _action("ai_system.invoke", {**_COMPLIANT, "use_case": "social_scoring"})
    )
    assert result.decision is Decision.DENY


async def test_high_risk_without_oversight_requires_approval():
    result = await _engine().evaluate(
        _action(
            "ai_system.invoke",
            {**_COMPLIANT, "risk_category": "high", "use_case": "credit_scoring", "human_oversight": False},
        )
    )
    assert result.decision is Decision.REQUIRE_APPROVAL


async def test_undisclosed_ai_requires_approval():
    result = await _engine().evaluate(
        _action("ai_system.invoke", {**_COMPLIANT, "discloses_ai": False})
    )
    assert result.decision is Decision.REQUIRE_APPROVAL


async def test_labeled_synthetic_content_allowed():
    result = await _engine().evaluate(
        _action("ai_content.generate", {"synthetic": True, "labeled": True})
    )
    assert result.decision is Decision.ALLOW


async def test_unlabeled_deepfake_requires_approval():
    result = await _engine().evaluate(
        _action("ai_content.generate", {"synthetic": True, "labeled": False})
    )
    assert result.decision is Decision.REQUIRE_APPROVAL
