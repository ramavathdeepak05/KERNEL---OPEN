"""Multi-worker seal linearization tests (D4-1).

Two `TrustLedger` instances sharing ONE `InMemoryLedgerRepository` simulate two uvicorn workers
(or Cloud Run instances) over one database. The repository's (tenant, ledger_seq) key is the
linearization point: a losing writer must detect the conflict, rehydrate, and retry — never
silently lose a seal or fork the log (the pre-D4-1 `ON CONFLICT DO NOTHING` behavior).
"""

from __future__ import annotations

import dataclasses

import pytest

from quaicu.adapters.ledger.memory_repo import InMemoryLedgerRepository
from quaicu.core.errors import LedgerSealError, LedgerSequenceConflictError
from quaicu.core.ledger.engine import TrustLedger
from quaicu.core.ledger.merkle import compute_root
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

TENANT = TenantId("acme")


def _action(n: int, tenant: str = "acme") -> Action:
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


def _two_workers() -> tuple[TrustLedger, TrustLedger, InMemoryLedgerRepository]:
    repo = InMemoryLedgerRepository()
    a = TrustLedger(signer=InMemoryEd25519Signer(), repository=repo)
    b = TrustLedger(signer=InMemoryEd25519Signer(), repository=repo)
    return a, b, repo


# ── Interleaved seals from two workers ──────────────────────────────────────────


async def test_interleaved_seals_lose_nothing() -> None:
    """Alternating seals from two stale-view workers: every seal lands, seqs dense."""
    a, b, repo = _two_workers()
    for n in range(6):
        worker = a if n % 2 == 0 else b
        await worker.seal(action=_action(n), evaluation=_evaluation(), recorded_result={})

    entries = await repo.load_tenant_entries(TENANT)
    assert [e.ledger_seq for e in entries] == list(range(6))
    assert {str(e.action_id) for e in entries} == {f"act-acme-{n}" for n in range(6)}


async def test_final_sth_matches_recomputed_root() -> None:
    """The durable STH signs exactly the tree built from the durable leaf hashes — no fork."""
    a, b, repo = _two_workers()
    for n in range(5):
        worker = a if n % 2 == 0 else b
        await worker.seal(action=_action(n), evaluation=_evaluation(), recorded_result={})

    entries = await repo.load_tenant_entries(TENANT)
    sth = (await repo.load_sths())["acme"]
    assert sth.tree_size == len(entries) == 5
    assert sth.root_hash == compute_root([e.leaf_hash for e in entries])


async def test_conflict_rehydrates_and_preserves_prefix_consistency() -> None:
    """After losing a race, a worker's tree is resynced — its proofs cover the winner's entries."""
    a, b, _repo = _two_workers()
    await a.seal(action=_action(0), evaluation=_evaluation(), recorded_result={})
    await a.seal(action=_action(1), evaluation=_evaluation(), recorded_result={})
    # b (view: empty tree, seq 0) seals — conflicts at 0, rehydrates, lands at seq 2.
    entry = await b.seal(action=_action(2), evaluation=_evaluation(), recorded_result={})
    assert entry.ledger_seq == 2
    # b now serves the full log, including a's entries, with verifying inclusion proofs.
    assert [e.ledger_seq for e in b.get_entries(TENANT)] == [0, 1, 2]
    sth = b.get_signed_tree_head(TENANT)
    for seq in range(3):
        assert b.verify_inclusion(TENANT, seq, sth)


async def test_tenants_do_not_contend() -> None:
    """Conflicts are per-tenant: parallel tenants on different workers never interfere (F-07)."""
    a, b, repo = _two_workers()
    for n in range(3):
        await a.seal(action=_action(n, "bank-a"), evaluation=_evaluation(), recorded_result={})
        await b.seal(action=_action(n, "bank-b"), evaluation=_evaluation(), recorded_result={})
    for tenant in ("bank-a", "bank-b"):
        entries = await repo.load_tenant_entries(TenantId(tenant))
        assert [e.ledger_seq for e in entries] == [0, 1, 2]


# ── Advance-only STH ────────────────────────────────────────────────────────────


async def test_stale_sth_save_cannot_regress_head() -> None:
    """A late save from a worker with a smaller tree is skipped (advance-only)."""
    a, b, repo = _two_workers()
    await a.seal(action=_action(0), evaluation=_evaluation(), recorded_result={})
    big = await repo.load_sths()
    await b.seal(action=_action(1), evaluation=_evaluation(), recorded_result={})
    # Replay a's earlier (size-1) STH after b advanced the head to size 2.
    await repo.save_sth(TENANT, big["acme"])
    stored = (await repo.load_sths())["acme"]
    assert stored.tree_size == 2  # not regressed


# ── Conflict semantics at the repository ────────────────────────────────────────


async def test_identical_replay_is_idempotent_success() -> None:
    a, _b, repo = _two_workers()
    entry = await a.seal(action=_action(0), evaluation=_evaluation(), recorded_result={})
    await repo.append_entry(entry)  # same (tenant, seq, leaf) — must not raise or duplicate
    assert len(await repo.load_tenant_entries(TENANT)) == 1


async def test_differing_entry_raises_typed_conflict() -> None:
    a, b, repo = _two_workers()
    await a.seal(action=_action(0), evaluation=_evaluation(), recorded_result={})
    losing = await b.seal(action=_action(1), evaluation=_evaluation(), recorded_result={})
    # Manually replay b's entry at a taken seq with a different leaf: typed conflict.
    forged = dataclasses.replace(losing, ledger_seq=0)
    with pytest.raises(LedgerSequenceConflictError):
        await repo.append_entry(forged)


# ── Fail-closed exhaustion ──────────────────────────────────────────────────────


class _AlwaysConflictRepo(InMemoryLedgerRepository):
    """Every append conflicts — simulates a pathologically hot slot / broken rehydrate."""

    async def append_entry(self, entry):  # type: ignore[no-untyped-def]
        raise LedgerSequenceConflictError(
            "injected permanent conflict",
            detail={"tenant": str(entry.tenant), "ledger_seq": entry.ledger_seq},
        )


async def test_conflict_exhaustion_halts_fail_closed() -> None:
    ledger = TrustLedger(signer=InMemoryEd25519Signer(), repository=_AlwaysConflictRepo())
    with pytest.raises(LedgerSealError):
        await ledger.seal(action=_action(0), evaluation=_evaluation(), recorded_result={})
    # In-memory state rolled back: no orphan leaves, no phantom entries.
    assert ledger.get_entries(TENANT) == []
