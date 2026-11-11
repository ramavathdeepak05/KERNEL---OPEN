"""Postgres StoragePort + ActionRepository adapter.

Implements both ``StoragePort`` and ``ActionRepository`` structurally on a single
asyncpg connection pool.  One pool per adapter instance; pool is created lazily on
first use (asyncpg.create_pool is async so we can't do it in __init__).

Tenant isolation:
  Every SQL statement carries an explicit ``tenant_id`` predicate.  The adapter
  additionally supports ``SET LOCAL quaicu.tenant_id`` for future RLS policies.

Fail-closed contract:
  All asyncpg exceptions are caught and re-raised as ``StoragePortError``.
  ``update_state`` raises if 0 rows were affected (action missing or wrong tenant).
  ``insert_if_absent`` uses INSERT … ON CONFLICT DO NOTHING — never double-inserts.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import asyncpg

from quaicu.core.errors import StoragePortError
from quaicu.core.types import (
    Action,
    ActionId,
    ActionState,
    Actor,
    ActorId,
    IdempotencyKey,
    TenantId,
)

# ── Serialisation helpers ─────────────────────────────────────────────────────


def _action_to_row(action: Action) -> dict[str, Any]:
    return {
        "id": str(action.id),
        "tenant_id": str(action.tenant),
        "idempotency_key": str(action.idempotency_key),
        "type": action.type,
        "state": action.state.value,
        "actor_id": str(action.actor.id),
        "actor_tenant": str(action.actor.tenant),
        "actor_roles": list(action.actor.roles),
        "actor_attributes": json.dumps(dict(action.actor.attributes)),
        "payload": json.dumps(dict(action.payload)),
        "proposed_at": action.proposed_at,
    }


def _row_to_action(row: asyncpg.Record) -> Action:
    actor = Actor(
        id=ActorId(row["actor_id"]),
        tenant=TenantId(row["actor_tenant"]),
        roles=tuple(row["actor_roles"] or []),
        attributes=json.loads(row["actor_attributes"]) if row["actor_attributes"] else {},
    )
    proposed_at: datetime | None = row["proposed_at"]
    if proposed_at is not None and proposed_at.tzinfo is None:
        proposed_at = proposed_at.replace(tzinfo=timezone.utc)
    return Action(
        id=ActionId(row["id"]),
        type=row["type"],
        payload=json.loads(row["payload"]) if row["payload"] else {},
        actor=actor,
        tenant=TenantId(row["tenant_id"]),
        idempotency_key=IdempotencyKey(row["idempotency_key"]),
        state=ActionState(row["state"]),
        proposed_at=proposed_at,
    )


# ── Transaction marker ────────────────────────────────────────────────────────


class _PostgresTransaction:
    """Satisfies the ``Transaction`` Protocol structurally.

    Holds the live asyncpg connection while the caller is inside
    ``async with storage.transaction() as txn:``.  Future layers can
    extend this with their own repository calls on the same connection.
    """

    def __init__(self, conn: asyncpg.Connection) -> None:
        self._conn = conn

    @property
    def conn(self) -> asyncpg.Connection:
        return self._conn


# ── Adapter ───────────────────────────────────────────────────────────────────

_INSERT_SQL = """
INSERT INTO quaicu_actions
    (id, tenant_id, idempotency_key, type, state,
     actor_id, actor_tenant, actor_roles, actor_attributes,
     payload, proposed_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
RETURNING id
"""

_SELECT_BY_IDEMPOTENCY_SQL = """
SELECT id, tenant_id, idempotency_key, type, state,
       actor_id, actor_tenant, actor_roles, actor_attributes,
       payload, proposed_at
FROM   quaicu_actions
WHERE  tenant_id = $1 AND idempotency_key = $2
"""

_SELECT_BY_ID_SQL = """
SELECT id, tenant_id, idempotency_key, type, state,
       actor_id, actor_tenant, actor_roles, actor_attributes,
       payload, proposed_at
FROM   quaicu_actions
WHERE  tenant_id = $1 AND id = $2
"""

_UPDATE_STATE_SQL = """
UPDATE quaicu_actions
SET    state = $1, updated_at = now()
WHERE  id = $2 AND tenant_id = $3
"""


class PostgresStorageAdapter:
    """Asyncpg-backed StoragePort + ActionRepository.

    Pass ``dsn`` as a libpq connection string or asyncpg DSN, e.g.::

        PostgresStorageAdapter(dsn="postgresql://quaicu:pass@localhost/quaicu")

    The pool is created lazily on first use.
    """

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None
        self._pool_lock = asyncio.Lock()

    # ── Pool lifecycle ────────────────────────────────────────────────────────

    async def _get_pool(self) -> asyncpg.Pool:
        if self._pool is not None:
            return self._pool
        async with self._pool_lock:
            if self._pool is None:
                try:
                    # Bounded pool — the kernel opens several pools against one database (actions,
                    # policies, ledger). asyncpg's default (10 each) exhausts a small instance.
                    self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=4)
                except Exception as exc:
                    raise StoragePortError(
                        f"Failed to create Postgres pool: {exc}",
                        detail={"dsn_prefix": self._dsn[:30]},
                    ) from exc
        return self._pool  # type: ignore[return-value]

    async def close(self) -> None:
        """Gracefully close the connection pool (call on shutdown)."""
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    # ── StoragePort ───────────────────────────────────────────────────────────

    @asynccontextmanager
    async def transaction(self):
        """Yield a ``_PostgresTransaction`` inside an asyncpg transaction.

        Commits on clean exit; rolls back on any exception.
        Wraps all asyncpg errors in ``StoragePortError``.
        """
        pool = await self._get_pool()
        try:
            async with pool.acquire() as conn:
                async with conn.transaction():
                    yield _PostgresTransaction(conn)
        except StoragePortError:
            raise
        except Exception as exc:
            raise StoragePortError(str(exc)) from exc

    async def health_check(self) -> bool:
        """Return True if Postgres is reachable; raise StoragePortError if not."""
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except StoragePortError:
            raise
        except Exception as exc:
            raise StoragePortError(
                f"Postgres health check failed: {exc}"
            ) from exc

    # ── ActionRepository ──────────────────────────────────────────────────────

    async def insert_if_absent(self, action: Action) -> Action | None:
        """Insert action; return None on success, return existing action on conflict."""
        row = _action_to_row(action)
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute("SELECT set_config('app.current_tenant', $1, true)", str(row["tenant_id"]))
                    result = await conn.fetchval(
                        _INSERT_SQL,
                        row["id"], row["tenant_id"], row["idempotency_key"],
                        row["type"], row["state"],
                        row["actor_id"], row["actor_tenant"], row["actor_roles"],
                        row["actor_attributes"], row["payload"], row["proposed_at"],
                    )
                    if result is not None:
                        # Clean insert — row was created
                        return None
                    # Conflict — fetch and return the existing action
                    existing = await conn.fetchrow(
                        _SELECT_BY_IDEMPOTENCY_SQL,
                        row["tenant_id"], row["idempotency_key"],
                    )
                if existing is None:
                    raise StoragePortError(
                        "insert_if_absent conflict but existing row not found",
                        detail={"tenant": row["tenant_id"], "key": row["idempotency_key"]},
                    )
                return _row_to_action(existing)
        except StoragePortError:
            raise
        except Exception as exc:
            raise StoragePortError(str(exc)) from exc

    async def update_state(self, action: Action) -> None:
        """Persist the action's current state. Raises StoragePortError if row not found."""
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute("SELECT set_config('app.current_tenant', $1, true)", str(action.tenant))
                    result = await conn.execute(
                        _UPDATE_STATE_SQL,
                        action.state.value, str(action.id), str(action.tenant),
                    )
            # asyncpg returns "UPDATE <count>" as a string
            count = int(result.split()[-1])
            if count == 0:
                raise StoragePortError(
                    "update_state affected 0 rows — action not found or wrong tenant",
                    detail={"action_id": str(action.id), "tenant": str(action.tenant)},
                )
        except StoragePortError:
            raise
        except Exception as exc:
            raise StoragePortError(str(exc)) from exc

    async def get_by_idempotency_key(
        self, tenant: TenantId, key: IdempotencyKey
    ) -> Action | None:
        """Return the action for (tenant, key) or None if not found."""
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute("SELECT set_config('app.current_tenant', $1, true)", str(tenant))
                    row = await conn.fetchrow(
                        _SELECT_BY_IDEMPOTENCY_SQL, str(tenant), str(key)
                    )
            return _row_to_action(row) if row is not None else None
        except StoragePortError:
            raise
        except Exception as exc:
            raise StoragePortError(str(exc)) from exc

    async def get_by_id(self, tenant: TenantId, action_id: ActionId) -> Action | None:
        """Return the (tenant, action_id) action or None. RLS-scoped via app.current_tenant."""
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute("SELECT set_config('app.current_tenant', $1, true)", str(tenant))
                    row = await conn.fetchrow(_SELECT_BY_ID_SQL, str(tenant), str(action_id))
            return _row_to_action(row) if row is not None else None
        except StoragePortError:
            raise
        except Exception as exc:
            raise StoragePortError(str(exc)) from exc
