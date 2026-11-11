"""Unit tests for PostgresStorageAdapter — no real database required.

All asyncpg calls are patched with AsyncMock so these run in the standard
pytest-asyncio suite without any external services.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from quaicu.adapters.storage.postgres import PostgresStorageAdapter, _action_to_row, _row_to_action
from quaicu.core.errors import StoragePortError
from quaicu.core.types import Action, ActionId, ActionState, Actor, ActorId, IdempotencyKey, TenantId

TENANT = TenantId("bank-a")
NOW = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)


def _actor(tenant: str = "bank-a") -> Actor:
    return Actor(id=ActorId("alice"), tenant=TenantId(tenant), roles=("role:analyst",))


def _action(
    tenant: str = "bank-a",
    ikey: str = "ik-1",
    state: ActionState = ActionState.PROPOSED,
) -> Action:
    return Action(
        id=ActionId("action-001"),
        type="loan.approve",
        payload={"amount": 1000},
        actor=_actor(tenant),
        tenant=TenantId(tenant),
        idempotency_key=IdempotencyKey(ikey),
        state=state,
        proposed_at=NOW,
    )


def _fake_pool(conn: AsyncMock) -> MagicMock:
    """Build a fake pool whose acquire() yields conn as an async context manager.

    Also wires ``conn.transaction()`` as an async context manager: the adapter opens a transaction to
    set the per-request RLS tenant context (``app.current_tenant``), so the mock must support it.
    """
    conn.transaction = MagicMock()
    conn.transaction.return_value.__aenter__ = AsyncMock(return_value=None)
    conn.transaction.return_value.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire_cm)
    return pool


# ── Serialisation round-trip ──────────────────────────────────────────────────


def test_action_to_row_and_back():
    action = _action()
    row_dict = _action_to_row(action)
    # Simulate an asyncpg Record-like mapping
    fake_row = {
        **row_dict,
        "actor_attributes": "{}",
        "payload": '{"amount": 1000}',
        "actor_roles": ["role:analyst"],
    }

    class FakeRecord(dict):
        pass

    back = _row_to_action(FakeRecord(fake_row))
    assert back.id == action.id
    assert back.tenant == action.tenant
    assert back.state == action.state
    assert back.actor.roles == ("role:analyst",)


# ── insert_if_absent ──────────────────────────────────────────────────────────


async def test_insert_if_absent_returns_none_on_clean_insert():
    conn = AsyncMock()
    conn.fetchval = AsyncMock(return_value="action-001")  # RETURNING id — row created

    adapter = PostgresStorageAdapter(dsn="postgresql://fake/fake")
    adapter._pool = _fake_pool(conn)

    result = await adapter.insert_if_absent(_action())
    assert result is None


async def test_insert_if_absent_returns_existing_on_conflict():
    action = _action()
    row = _action_to_row(action)
    fake_record = {
        **row,
        "actor_attributes": "{}",
        "payload": '{"amount": 1000}',
        "actor_roles": ["role:analyst"],
    }

    conn = AsyncMock()
    conn.fetchval = AsyncMock(return_value=None)  # ON CONFLICT → no RETURNING row
    conn.fetchrow = AsyncMock(return_value=fake_record)

    adapter = PostgresStorageAdapter(dsn="postgresql://fake/fake")
    adapter._pool = _fake_pool(conn)

    existing = await adapter.insert_if_absent(action)
    assert existing is not None
    assert existing.id == action.id
    assert existing.idempotency_key == action.idempotency_key


async def test_insert_if_absent_wraps_asyncpg_error():
    conn = AsyncMock()
    conn.fetchval = AsyncMock(side_effect=Exception("connection reset"))

    adapter = PostgresStorageAdapter(dsn="postgresql://fake/fake")
    adapter._pool = _fake_pool(conn)

    with pytest.raises(StoragePortError, match="connection reset"):
        await adapter.insert_if_absent(_action())


# ── update_state ──────────────────────────────────────────────────────────────


async def test_update_state_succeeds():
    conn = AsyncMock()
    conn.execute = AsyncMock(return_value="UPDATE 1")

    adapter = PostgresStorageAdapter(dsn="postgresql://fake/fake")
    adapter._pool = _fake_pool(conn)

    await adapter.update_state(_action(state=ActionState.COMPLETED))  # no exception


async def test_update_state_raises_on_zero_rows():
    conn = AsyncMock()
    conn.execute = AsyncMock(return_value="UPDATE 0")

    adapter = PostgresStorageAdapter(dsn="postgresql://fake/fake")
    adapter._pool = _fake_pool(conn)

    with pytest.raises(StoragePortError, match="0 rows"):
        await adapter.update_state(_action(state=ActionState.DENIED))


# ── get_by_idempotency_key ────────────────────────────────────────────────────


async def test_get_by_idempotency_key_returns_action():
    action = _action()
    row = _action_to_row(action)
    fake_record = {
        **row,
        "actor_attributes": "{}",
        "payload": '{"amount": 1000}',
        "actor_roles": ["role:analyst"],
    }

    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=fake_record)

    adapter = PostgresStorageAdapter(dsn="postgresql://fake/fake")
    adapter._pool = _fake_pool(conn)

    result = await adapter.get_by_idempotency_key(TENANT, IdempotencyKey("ik-1"))
    assert result is not None
    assert result.id == action.id


async def test_get_by_idempotency_key_returns_none_when_missing():
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=None)

    adapter = PostgresStorageAdapter(dsn="postgresql://fake/fake")
    adapter._pool = _fake_pool(conn)

    result = await adapter.get_by_idempotency_key(TENANT, IdempotencyKey("no-such-key"))
    assert result is None


# ── health_check ──────────────────────────────────────────────────────────────


async def test_health_check_returns_true():
    conn = AsyncMock()
    conn.execute = AsyncMock(return_value=None)

    adapter = PostgresStorageAdapter(dsn="postgresql://fake/fake")
    adapter._pool = _fake_pool(conn)

    assert await adapter.health_check() is True


async def test_health_check_raises_storage_port_error_on_failure():
    conn = AsyncMock()
    conn.execute = AsyncMock(side_effect=Exception("server closed"))

    adapter = PostgresStorageAdapter(dsn="postgresql://fake/fake")
    adapter._pool = _fake_pool(conn)

    with pytest.raises(StoragePortError, match="server closed"):
        await adapter.health_check()


# ── transaction() ─────────────────────────────────────────────────────────────


async def test_transaction_yields_postgres_transaction():
    from quaicu.adapters.storage.postgres import _PostgresTransaction

    conn = AsyncMock()
    txn_cm = MagicMock()
    txn_cm.__aenter__ = AsyncMock(return_value=None)
    txn_cm.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn_cm)

    adapter = PostgresStorageAdapter(dsn="postgresql://fake/fake")
    adapter._pool = _fake_pool(conn)

    async with adapter.transaction() as txn:
        assert isinstance(txn, _PostgresTransaction)


async def test_transaction_wraps_exception_as_storage_port_error():
    conn = AsyncMock()
    adapter = PostgresStorageAdapter(dsn="postgresql://fake/fake")
    adapter._pool = _fake_pool(conn)
    # Override _fake_pool's default txn with one whose enter raises (e.g. a deadlock), set AFTER the
    # helper so it isn't clobbered.
    txn_cm = MagicMock()
    txn_cm.__aenter__ = AsyncMock(side_effect=Exception("deadlock"))
    txn_cm.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn_cm)

    with pytest.raises(StoragePortError, match="deadlock"):
        async with adapter.transaction():
            pass
