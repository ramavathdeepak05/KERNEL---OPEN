"""Guards the shipped DPDP starter policy pack (quaicu/policy_packs/dpdp/policies.toml).

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

_PACK = Path(__file__).resolve().parents[3] / "quaicu" / "policy_packs" / "dpdp" / "policies.toml"


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
        actor=Actor(id=ActorId("svc"), tenant=TenantId("acme"), roles=("role:processor",)),
        tenant=TenantId("acme"),
        idempotency_key=IdempotencyKey("ik-1"),
    )


_COMPLIANT = {"consent_obtained": True, "purpose": "kyc", "subject_erased": False}


async def test_pack_compiles_and_seeds():
    engine = _engine()  # raises if any CEL is invalid
    assert engine._store.lookup("personal_data.process", "acme")  # policies present


async def test_compliant_processing_allowed():
    result = await _engine().evaluate(_action("personal_data.process", _COMPLIANT))
    assert result.decision is Decision.ALLOW


async def test_missing_consent_denied():
    result = await _engine().evaluate(
        _action("personal_data.process", {**_COMPLIANT, "consent_obtained": False})
    )
    assert result.decision is Decision.DENY


async def test_disallowed_purpose_denied():
    result = await _engine().evaluate(
        _action("personal_data.process", {**_COMPLIANT, "purpose": "marketing"})
    )
    assert result.decision is Decision.DENY


async def test_erased_subject_denied():
    result = await _engine().evaluate(
        _action("personal_data.process", {**_COMPLIANT, "subject_erased": True})
    )
    assert result.decision is Decision.DENY


async def test_domestic_transfer_allowed():
    result = await _engine().evaluate(
        _action("personal_data.transfer", {"destination_country": "IN"})
    )
    assert result.decision is Decision.ALLOW


async def test_cross_border_transfer_requires_approval():
    result = await _engine().evaluate(
        _action("personal_data.transfer", {"destination_country": "US"})
    )
    assert result.decision is Decision.REQUIRE_APPROVAL
