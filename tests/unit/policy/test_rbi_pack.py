"""Guards the shipped RBI/SEBI starter policy pack (quaicu/policy_packs/rbi/policies.toml).

Loads the pack, seeds it into a PolicyStore (which compiles the CEL — so this catches a broken
expression), and asserts the documented compliance behavior end-to-end across all four action types.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from quaicu.core.policy.evaluator import PolicyEngine
from quaicu.core.policy.store import PolicyStore
from quaicu.core.types import Action, ActionId, Actor, ActorId, Decision, IdempotencyKey, TenantId
from quaicu.delivery.sdk.kernel import Kernel

_PACK = Path(__file__).resolve().parents[3] / "quaicu" / "policy_packs" / "rbi" / "policies.toml"


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


# Fully-compliant payloads per action type (in India, encrypted, audited, exit-planned, logged).
_STORE_OK = {"data_class": "payment", "storage_region": "IN", "encryption_at_rest": True}
_OUTSOURCING_OK = {"material": False, "audit_rights": True, "exit_plan": True}


async def test_pack_compiles_and_seeds():
    engine = _engine()  # raises if any CEL is invalid
    assert engine._store.lookup("data.store", "acme")  # policies present
    assert engine._store.lookup("outsourcing.engage", "acme")


# ── data.store ───────────────────────────────────────────────────────────────────
async def test_compliant_payment_store_allowed():
    result = await _engine().evaluate(_action("data.store", _STORE_OK))
    assert result.decision is Decision.ALLOW


async def test_payment_data_stored_abroad_denied():
    result = await _engine().evaluate(
        _action("data.store", {**_STORE_OK, "storage_region": "US"})
    )
    assert result.decision is Decision.DENY


async def test_unencrypted_store_denied():
    result = await _engine().evaluate(
        _action("data.store", {**_STORE_OK, "encryption_at_rest": False})
    )
    assert result.decision is Decision.DENY


async def test_regulated_data_abroad_requires_approval():
    # Non-payment regulated data stored outside India: reviewed (not the hard payment deny).
    result = await _engine().evaluate(
        _action("data.store", {"data_class": "kyc", "storage_region": "US", "encryption_at_rest": True})
    )
    assert result.decision is Decision.REQUIRE_APPROVAL


async def test_non_regulated_data_abroad_allowed():
    result = await _engine().evaluate(
        _action("data.store", {"data_class": "other", "storage_region": "US", "encryption_at_rest": True})
    )
    assert result.decision is Decision.ALLOW


# ── data.transfer ────────────────────────────────────────────────────────────────
async def test_domestic_transfer_allowed():
    result = await _engine().evaluate(_action("data.transfer", {"destination_country": "IN"}))
    assert result.decision is Decision.ALLOW


async def test_cross_border_transfer_requires_approval():
    result = await _engine().evaluate(_action("data.transfer", {"destination_country": "US"}))
    assert result.decision is Decision.REQUIRE_APPROVAL


# ── outsourcing.engage ───────────────────────────────────────────────────────────
async def test_compliant_outsourcing_allowed():
    result = await _engine().evaluate(_action("outsourcing.engage", _OUTSOURCING_OK))
    assert result.decision is Decision.ALLOW


async def test_material_outsourcing_requires_approval():
    result = await _engine().evaluate(
        _action("outsourcing.engage", {**_OUTSOURCING_OK, "material": True})
    )
    assert result.decision is Decision.REQUIRE_APPROVAL


async def test_outsourcing_without_audit_rights_denied():
    result = await _engine().evaluate(
        _action("outsourcing.engage", {**_OUTSOURCING_OK, "audit_rights": False})
    )
    assert result.decision is Decision.DENY


async def test_outsourcing_without_exit_plan_denied():
    result = await _engine().evaluate(
        _action("outsourcing.engage", {**_OUTSOURCING_OK, "exit_plan": False})
    )
    assert result.decision is Decision.DENY


# ── access.grant ─────────────────────────────────────────────────────────────────
async def test_logged_access_grant_allowed():
    result = await _engine().evaluate(_action("access.grant", {"access_logged": True}))
    assert result.decision is Decision.ALLOW


async def test_unlogged_access_grant_denied():
    result = await _engine().evaluate(_action("access.grant", {"access_logged": False}))
    assert result.decision is Decision.DENY
