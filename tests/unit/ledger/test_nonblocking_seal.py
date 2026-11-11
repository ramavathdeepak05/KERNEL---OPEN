"""W8-1 — seal must not block the event loop while the signer makes its (blocking) network call.

A durable signer (Cloud KMS / OpenBao) signs with a synchronous network round-trip. `TrustLedger.seal`
runs `sign` via `asyncio.to_thread`, so other coroutines keep running during a seal. This test proves it:
with a signer whose `sign` blocks for ~150ms, a concurrent ticker still advances — and the seal still
produces a valid, correctly-signed entry.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime

from quaicu.core.ledger.engine import TrustLedger
from quaicu.core.ledger.signer import InMemoryEd25519Signer, SignedTreeHead
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

_T = TenantId("alpha")


def _action() -> Action:
    return Action(
        id=ActionId("act-001"),
        type="test.action",
        payload={},
        actor=Actor(id=ActorId("actor-1"), tenant=_T),
        tenant=_T,
        idempotency_key=IdempotencyKey("idem-001"),
        state=ActionState.SEALING,
    )


class _BlockingSigner:
    """A TreeSigner whose sign() blocks (stands in for a Cloud KMS / OpenBao network round-trip)."""

    def __init__(self, delay: float = 0.15) -> None:
        self._inner = InMemoryEd25519Signer()
        self._delay = delay

    def sign(self, tree_size: int, root_hash: bytes, timestamp: datetime) -> SignedTreeHead:
        time.sleep(self._delay)  # blocking I/O stand-in — must NOT freeze the event loop
        return self._inner.sign(tree_size, root_hash, timestamp)

    def verify(self, sth: SignedTreeHead) -> bool:
        return self._inner.verify(sth)

    @property
    def key_id(self) -> str:
        return self._inner.key_id

    @property
    def public_key_pem(self) -> str:
        return self._inner.public_key_pem


async def test_seal_does_not_block_the_event_loop() -> None:
    ledger = TrustLedger(signer=_BlockingSigner(delay=0.15))
    ticks = 0
    done = asyncio.Event()

    async def ticker() -> None:
        nonlocal ticks
        while not done.is_set():
            await asyncio.sleep(0.005)
            ticks += 1

    t = asyncio.create_task(ticker())
    try:
        entry = await ledger.seal(action=_action(), evaluation=EvaluationResult(
            decision=Decision.ALLOW, policy_versions=("v1.0",)
        ), recorded_result={})
    finally:
        done.set()
        await t

    # Correctness: the seal completed and the STH verifies.
    assert entry.ledger_seq == 0  # first entry in the per-tenant log
    sth = ledger.get_signed_tree_head(_T)
    assert sth is not None and ledger._signer.verify(sth)  # type: ignore[attr-defined]
    # Non-blocking: the loop ran many ticks during the ~150ms blocking sign (≈30 at 5ms cadence).
    # If `sign` blocked the loop (the pre-W8-1 bug), the ticker would barely advance.
    assert ticks >= 5, f"event loop appears blocked during seal (ticks={ticks})"
