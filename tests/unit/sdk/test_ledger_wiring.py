"""Kernel wiring for durable ledger persistence (ADR-0008).

Proves that `kernel.startup()` hydrates the wired ledger from its repository and that
`kernel.shutdown()` releases resources without error.
"""

from __future__ import annotations

from quaicu.adapters.ledger.memory_repo import InMemoryLedgerRepository
from quaicu.core.ledger.engine import TrustLedger
from quaicu.core.ledger.signer import InMemoryEd25519Signer
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
from quaicu.delivery.sdk.kernel import Kernel

from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeIdentity, FakePolicy

TENANT = TenantId("acme")


def _action() -> Action:
    return Action(
        id=ActionId("act-0"),
        type="payments.wire",
        payload={"amount": 100},
        actor=Actor(id=ActorId("alice"), tenant=TENANT, roles=("role:maker",)),
        tenant=TENANT,
        idempotency_key=IdempotencyKey("k-0"),
        state=ActionState.SEALING,
    )


async def test_startup_hydrates_ledger_from_repository() -> None:
    # Pre-seed a repository via one ledger, then wire a fresh ledger over the same repository.
    repo = InMemoryLedgerRepository()
    seeded = TrustLedger(signer=InMemoryEd25519Signer(), repository=repo)
    await seeded.seal(
        action=_action(),
        evaluation=EvaluationResult(decision=Decision.ALLOW, policy_versions=("p@v1",)),
        recorded_result={},
    )

    fresh_ledger = TrustLedger(signer=InMemoryEd25519Signer(), repository=repo)
    kernel = Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(),
        hitl=FakeHITL(),
        ledger=fresh_ledger,
        events=FakeEvents(),
        identity=FakeIdentity(),
        ledger_repository=repo,
    )
    assert kernel.ledger_repository is repo
    assert fresh_ledger.get_entries(TENANT) == []  # not hydrated yet

    await kernel.startup()
    assert len(fresh_ledger.get_entries(TENANT)) == 1  # hydrated on startup

    await kernel.shutdown()  # must not raise (best-effort close)
