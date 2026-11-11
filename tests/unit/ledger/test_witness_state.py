"""Durable witness state (D3-2 follow-up): a rewind is still caught after a witness restart."""

from __future__ import annotations

import dataclasses

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from quaicu.adapters.ledger.witness import SoftwareWitness
from quaicu.core.errors import LedgerTamperError
from quaicu.core.ledger.anchor import InMemoryWitnessStateStore, anchor_current_sth
from quaicu.core.ledger.engine import TrustLedger
from quaicu.core.types import (
    Action,
    ActionId,
    ActionState,
    Actor,
    ActorId,
    Decision,
    EvaluationResult,
    IdempotencyKey,
    TenantId,
)

T = TenantId("ciro-bank")


def _key_pem() -> str:
    return Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


async def _ledger(n: int) -> TrustLedger:
    ledger = TrustLedger()
    for i in range(n):
        await ledger.seal(
            action=Action(id=ActionId(f"a{i}"), type="x", payload={"n": i},
                          actor=Actor(id=ActorId("u"), tenant=T), tenant=T,
                          idempotency_key=IdempotencyKey(f"i{i}"), state=ActionState.SEALING),
            evaluation=EvaluationResult(decision=Decision.ALLOW, policy_versions=("v1",)),
            recorded_result={},
        )
    return ledger


def test_inmemory_store_is_monotonic():
    store = InMemoryWitnessStateStore()
    store.advance(T, 5, b"\x05" * 32)
    store.advance(T, 3, b"\x03" * 32)  # regression ignored
    assert store.get(T) == (5, b"\x05" * 32)
    store.advance(T, 7, b"\x07" * 32)
    assert store.get(T) == (7, b"\x07" * 32)


async def test_rewind_caught_after_restart_with_durable_state():
    ledger = await _ledger(3)
    store = InMemoryWitnessStateStore()  # stands in for the durable store shared across restarts
    pem = _key_pem()

    w1 = SoftwareWitness(private_key_pem=pem, witness_id="witness:x", state_store=store)
    anchor_current_sth(ledger, w1, T)  # cosigns size 3; store now remembers it

    # "Restart": a fresh witness object, SAME durable store + SAME key (stable pin).
    w2 = SoftwareWitness(private_key_pem=pem, witness_id="witness:x", state_store=store)
    assert w2.last_seen(T)[0] == 3  # memory survived the restart
    stale = dataclasses.replace(ledger.get_signed_tree_head(T), tree_size=1)
    with pytest.raises(LedgerTamperError):
        w2.cosign(T, stale, [])  # rewind still refused


async def test_without_durable_state_a_restart_would_miss_the_rewind():
    # Contrast: a restarted witness with a FRESH store has no memory → cosigns the rewind. This is
    # exactly the hole the durable store closes.
    ledger = await _ledger(3)
    pem = _key_pem()
    w1 = SoftwareWitness(private_key_pem=pem, state_store=InMemoryWitnessStateStore())
    anchor_current_sth(ledger, w1, T)

    w_restarted = SoftwareWitness(private_key_pem=pem, state_store=InMemoryWitnessStateStore())
    stale = dataclasses.replace(ledger.get_signed_tree_head(T), tree_size=1)
    cosig = w_restarted.cosign(T, stale, [])  # no memory → treated as a fresh first STH
    assert cosig.tree_size == 1
