"""Storage adapter conformance tests — spec-derived golden cases.

These tests verify the ``ActionRepository`` contract against a real Postgres
instance.  They are skipped unless the ``DATABASE_URL`` environment variable
is set and the ``quaicu_actions`` table exists (run migrations first).

Run::

    DATABASE_URL=postgresql://quaicu:quaicu-dev@localhost/quaicu \\
        pytest tests/conformance/storage/ -m integration -v

Invariants tested:
  - Insert and retrieve by idempotency key (basic persistence).
  - Idempotency: second insert with same key returns the first action.
  - update_state persists the new state.
  - Cross-tenant isolation: tenant-A's action is invisible to tenant-B.
  - health_check returns True on a live connection.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from quaicu.adapters.storage.postgres import PostgresStorageAdapter
from quaicu.core.types import Action, ActionId, ActionState, Actor, ActorId, IdempotencyKey, TenantId

DATABASE_URL = os.environ.get("DATABASE_URL", "")
skip_no_db = pytest.mark.skipif(
    not DATABASE_URL,
    reason="DATABASE_URL not set — skipping integration tests",
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)


def _actor(tenant: str) -> Actor:
    return Actor(id=ActorId("alice"), tenant=TenantId(tenant), roles=("role:analyst",))


def _action(tenant: str, ikey: str, state: ActionState = ActionState.PROPOSED) -> Action:
    return Action(
        id=ActionId(f"action-{tenant}-{ikey}"),
        type="loan.approve",
        payload={"amount": 5000},
        actor=_actor(tenant),
        tenant=TenantId(tenant),
        idempotency_key=IdempotencyKey(ikey),
        state=state,
        proposed_at=NOW,
    )


@pytest.fixture
async def adapter():
    a = PostgresStorageAdapter(dsn=DATABASE_URL)
    yield a
    # Clean up test rows
    pool = await a._get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("ALTER TABLE quaicu_actions NO FORCE ROW LEVEL SECURITY")
            await conn.execute("SET LOCAL row_security = off")
            await conn.execute(
                "DELETE FROM quaicu_actions WHERE tenant_id LIKE 'test-%'"
            )
            await conn.execute("ALTER TABLE quaicu_actions FORCE ROW LEVEL SECURITY")
    await a.close()


@pytest.mark.integration
@skip_no_db
async def test_insert_and_retrieve(adapter: PostgresStorageAdapter):
    action = _action("test-bank-a", "ik-conform-001")
    result = await adapter.insert_if_absent(action)
    assert result is None  # clean insert

    fetched = await adapter.get_by_idempotency_key(
        TenantId("test-bank-a"), IdempotencyKey("ik-conform-001")
    )
    assert fetched is not None
    assert fetched.id == action.id
    assert fetched.type == "loan.approve"
    assert fetched.state == ActionState.PROPOSED


@pytest.mark.integration
@skip_no_db
async def test_idempotency_returns_existing(adapter: PostgresStorageAdapter):
    action = _action("test-bank-a", "ik-conform-002")
    await adapter.insert_if_absent(action)

    # Second insert with same key must return the first action, not None
    existing = await adapter.insert_if_absent(action)
    assert existing is not None
    assert existing.id == action.id


@pytest.mark.integration
@skip_no_db
async def test_update_state_persists(adapter: PostgresStorageAdapter):
    action = _action("test-bank-a", "ik-conform-003")
    await adapter.insert_if_absent(action)

    updated = action.with_state(ActionState.COMPLETED)
    await adapter.update_state(updated)

    fetched = await adapter.get_by_idempotency_key(
        TenantId("test-bank-a"), IdempotencyKey("ik-conform-003")
    )
    assert fetched is not None
    assert fetched.state == ActionState.COMPLETED


@pytest.mark.integration
@skip_no_db
async def test_cross_tenant_isolation(adapter: PostgresStorageAdapter):
    """Action inserted for tenant-A must NOT be visible to tenant-B (F-07)."""
    action = _action("test-bank-a", "ik-conform-004")
    await adapter.insert_if_absent(action)

    result = await adapter.get_by_idempotency_key(
        TenantId("test-bank-b"), IdempotencyKey("ik-conform-004")
    )
    assert result is None


@pytest.mark.integration
@skip_no_db
async def test_health_check_live(adapter: PostgresStorageAdapter):
    assert await adapter.health_check() is True
