"""Unit tests for durable ledger persistence (ADR-0008).

Exercises the TrustLedger write-through + hydrate path against the InMemoryLedgerRepository (no DB)
and proves the fail-closed rollback when the durable write fails.
"""

from __future__ import annotations

import pytest

from quaicu.adapters.ledger.memory_repo import InMemoryLedgerRepository
from quaicu.core.errors import LedgerPersistenceError, LedgerSealError
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


def _action(tenant: str, n: int) -> Action:
    t = TenantId(tenant)
    return Action(
        id=ActionId(f"act-{tenant}-{n}"),
        type="payments.wire",
        payload={"amount": 100 + n},
        actor=Actor(id=ActorId("alice"), tenant=t, roles=("role:maker",)),
        tenant=t,
        idempotency_key=IdempotencyKey(f"k-{tenant}-{n}"),
        state=ActionState.SEALING,
    )


def _evaluation() -> EvaluationResult:
    return EvaluationResult(decision=Decision.ALLOW, policy_versions=("p@v1",))


class _FailingRepo(InMemoryLedgerRepository):
    """Repository whose entry write fails, to prove fail-closed rollback."""

    async def append_entry(self, entry):  # type: ignore[no-untyped-def]
        raise LedgerPersistenceError("injected durable write fault")


# ── Write-through ────────────────────────────────────────────────────────────────


async def test_seal_persists_entry_and_sth() -> None:
    repo = InMemoryLedgerRepository()
    ledger = TrustLedger(signer=InMemoryEd25519Signer(), repository=repo)
    await ledger.seal(action=_action("acme", 0), evaluation=_evaluation(), recorded_result={})

    entries = await repo.load_entries()
    sths = await repo.load_sths()
    assert len(entries) == 1
    assert entries[0].ledger_seq == 0
    assert "acme" in sths


async def test_seal_without_repository_unchanged() -> None:
    ledger = TrustLedger(signer=InMemoryEd25519Signer())  # no repository
    entry = await ledger.seal(
        action=_action("acme", 0), evaluation=_evaluation(), recorded_result={}
    )
    assert entry.ledger_seq == 0
    assert len(ledger.get_entries(TenantId("acme"))) == 1


# ── Hydrate round-trip ───────────────────────────────────────────────────────────


async def test_hydrate_rebuilds_entries_and_proofs() -> None:
    repo = InMemoryLedgerRepository()
    signer = InMemoryEd25519Signer()
    source = TrustLedger(signer=signer, repository=repo)
    tenant = TenantId("acme")
    for n in range(4):
        await source.seal(action=_action("acme", n), evaluation=_evaluation(), recorded_result={})
    source_sth = source.get_signed_tree_head(tenant)

    # A fresh ledger (simulating a restart) rebuilds purely from the repository.
    restored = TrustLedger(signer=InMemoryEd25519Signer(), repository=repo)
    await restored.hydrate()

    entries = restored.get_entries(tenant)
    assert [e.ledger_seq for e in entries] == [0, 1, 2, 3]
    assert [str(e.action_id) for e in entries] == [f"act-acme-{n}" for n in range(4)]
    # The restored STH matches the one persisted before "restart".
    assert restored.get_signed_tree_head(tenant).root_hash == source_sth.root_hash
    # Inclusion proofs still verify against the rebuilt tree + restored head.
    for seq in range(4):
        assert restored.verify_inclusion(tenant, seq, restored.get_signed_tree_head(tenant))


async def test_hydrate_preserves_tenant_isolation() -> None:
    repo = InMemoryLedgerRepository()
    source = TrustLedger(signer=InMemoryEd25519Signer(), repository=repo)
    await source.seal(action=_action("bank-a", 0), evaluation=_evaluation(), recorded_result={})
    await source.seal(action=_action("bank-b", 0), evaluation=_evaluation(), recorded_result={})
    await source.seal(action=_action("bank-a", 1), evaluation=_evaluation(), recorded_result={})

    restored = TrustLedger(signer=InMemoryEd25519Signer(), repository=repo)
    await restored.hydrate()

    assert len(restored.get_entries(TenantId("bank-a"))) == 2
    assert len(restored.get_entries(TenantId("bank-b"))) == 1
    # Next seq continues from the persisted max (no collision after restart).
    await restored.seal(action=_action("bank-a", 2), evaluation=_evaluation(), recorded_result={})
    assert [e.ledger_seq for e in restored.get_entries(TenantId("bank-a"))] == [0, 1, 2]


async def test_hydrate_no_repository_is_noop() -> None:
    ledger = TrustLedger(signer=InMemoryEd25519Signer())
    await ledger.hydrate()  # must not raise
    assert ledger.get_entries(TenantId("acme")) == []


# ── Fail-closed rollback ─────────────────────────────────────────────────────────


async def test_persistence_failure_halts_and_rolls_back() -> None:
    ledger = TrustLedger(signer=InMemoryEd25519Signer(), repository=_FailingRepo())
    tenant = TenantId("acme")
    with pytest.raises(LedgerSealError):
        await ledger.seal(action=_action("acme", 0), evaluation=_evaluation(), recorded_result={})
    # In-memory state was rolled back — no orphan leaf or entry, seq did not advance.
    assert ledger.get_entries(tenant) == []
    # A subsequent successful seal (swap to a healthy repo) starts cleanly at seq 0.
    ledger._repository = InMemoryLedgerRepository()  # type: ignore[attr-defined]
    entry = await ledger.seal(
        action=_action("acme", 1), evaluation=_evaluation(), recorded_result={}
    )
    assert entry.ledger_seq == 0
