"""Durable ledger conformance tests — real Postgres round-trip (ADR-0008).

Skipped unless ``DATABASE_URL`` is set and migration 003 has been applied
(``quaicu_ledger_entries`` + ``quaicu_ledger_sth`` must exist). Run::

    DATABASE_URL=postgresql://quaicu:quaicu-dev@localhost/quaicu \\
        pytest tests/conformance/ledger/test_postgres_spec.py -m integration -v

Invariant tested: seal-through-Postgres then hydrate a fresh TrustLedger from the same DSN —
entries, sequence, the signed tree head, and an inclusion proof all survive a simulated restart.
"""

from __future__ import annotations

import os

import pytest

from quaicu.adapters.ledger.postgres import PostgresLedgerRepository
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

DATABASE_URL = os.environ.get("DATABASE_URL", "")
skip_no_db = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set — skipping integration tests"
)

TENANT = "test-ledger-bank"


def _action(n: int) -> Action:
    t = TenantId(TENANT)
    return Action(
        id=ActionId(f"act-{n}"),
        type="payments.wire",
        payload={"amount": 100 + n},
        actor=Actor(id=ActorId("alice"), tenant=t, roles=("role:maker",)),
        tenant=t,
        idempotency_key=IdempotencyKey(f"k-{n}"),
        state=ActionState.SEALING,
    )


def _evaluation() -> EvaluationResult:
    return EvaluationResult(decision=Decision.ALLOW, policy_versions=("p@v1",))


@pytest.fixture
async def repo():
    r = PostgresLedgerRepository(dsn=DATABASE_URL)
    yield r
    pool = await r._get_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM quaicu_ledger_entries WHERE tenant_id = $1", TENANT)
        await conn.execute("DELETE FROM quaicu_ledger_sth WHERE tenant_id = $1", TENANT)
    await r.close()


@pytest.mark.integration
@skip_no_db
async def test_seal_then_hydrate_survives_restart(repo: PostgresLedgerRepository):
    tenant = TenantId(TENANT)
    source = TrustLedger(signer=InMemoryEd25519Signer(), repository=repo)
    for n in range(3):
        await source.seal(action=_action(n), evaluation=_evaluation(), recorded_result={"n": n})
    source_root = source.get_signed_tree_head(tenant).root_hash

    # Simulate a restart: a brand-new ledger rebuilt purely from Postgres.
    restored = TrustLedger(signer=InMemoryEd25519Signer(), repository=repo)
    await restored.hydrate()

    entries = restored.get_entries(tenant)
    assert [e.ledger_seq for e in entries] == [0, 1, 2]
    assert restored.get_signed_tree_head(tenant).root_hash == source_root
    assert restored.verify_inclusion(tenant, 1, restored.get_signed_tree_head(tenant))
