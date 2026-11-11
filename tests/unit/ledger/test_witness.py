"""Independent witness cosigning (D3-2): cosigns genuine growth, refuses a fork/rewind."""

from __future__ import annotations

import dataclasses

import pytest

from quaicu.adapters.ledger.witness import SoftwareWitness
from quaicu.core.errors import LedgerTamperError
from quaicu.core.ledger.anchor import anchor_current_sth
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


def _action(n: int) -> Action:
    return Action(
        id=ActionId(f"a{n}"), type="loan.approve", payload={"amount": n},
        actor=Actor(id=ActorId("alice"), tenant=T), tenant=T,
        idempotency_key=IdempotencyKey(f"i{n}"), state=ActionState.SEALING,
    )


async def _ledger_with(n: int) -> TrustLedger:
    ledger = TrustLedger()
    for i in range(n):
        await ledger.seal(
            action=_action(i),
            evaluation=EvaluationResult(decision=Decision.ALLOW, policy_versions=("v1",)),
            recorded_result={},
        )
    return ledger


async def test_cosigns_honest_growth_and_verifies():
    ledger = await _ledger_with(1)
    witness = SoftwareWitness()
    cosig = anchor_current_sth(ledger, witness, T)
    assert cosig.tree_size == 1
    assert witness.verify(cosig, witness.public_key_pem)
    # A cosignature does not verify against a different witness's key.
    assert not witness.verify(cosig, SoftwareWitness().public_key_pem)

    # Grow the log and re-anchor across several appends — each is a consistent extension.
    for i in range(1, 4):
        await ledger.seal(
            action=_action(100 + i),
            evaluation=EvaluationResult(decision=Decision.ALLOW, policy_versions=("v1",)),
            recorded_result={},
        )
        cosig = anchor_current_sth(ledger, witness, T)
        assert witness.verify(cosig, witness.public_key_pem)
    assert witness.last_seen(T)[0] == cosig.tree_size == 4


async def test_refuses_rewind():
    ledger = await _ledger_with(3)
    witness = SoftwareWitness()
    anchor_current_sth(ledger, witness, T)  # witness now anchored at size 3
    # Present a stale, smaller STH (a rewind) → refused.
    stale = dataclasses.replace(ledger.get_signed_tree_head(T), tree_size=1)
    with pytest.raises(LedgerTamperError):
        witness.cosign(T, stale, [])


async def test_refuses_same_size_fork():
    ledger = await _ledger_with(2)
    witness = SoftwareWitness()
    anchor_current_sth(ledger, witness, T)
    sth = ledger.get_signed_tree_head(T)
    forked = dataclasses.replace(sth, root_hash=bytes([sth.root_hash[0] ^ 1]) + sth.root_hash[1:])
    with pytest.raises(LedgerTamperError):
        witness.cosign(T, forked, [])  # same size, different root → split-view
