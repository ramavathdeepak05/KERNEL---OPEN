"""PostgresLedgerRepository — durable, asyncpg-backed ledger persistence (K·02).

Implements the `LedgerRepository` Protocol structurally on a single asyncpg connection pool (created
lazily on first use). Mirrors `adapters/policy/postgres.py` and `adapters/storage/postgres.py`.

Tables (see migration 003_create_ledger_tables.py):
  quaicu_ledger_entries  — one row per (tenant_id, ledger_seq); a sealed LedgerEntry.
  quaicu_ledger_sth      — one row per tenant_id; the latest Signed Tree Head.

Tenant isolation (F-07): every row carries `tenant_id`; the primary keys and reads are tenant-scoped
(same logical-isolation posture as the shipped `quaicu_actions` table). Physical schema-per-tenant is
a documented hardening follow-up (ADR-0008).

Fail-closed contract: all asyncpg exceptions are wrapped in `LedgerPersistenceError`.

Multi-worker linearization (D4-1): the (tenant_id, ledger_seq) PK arbitrates concurrent seals from
different workers/instances. `append_entry` detects a lost insert (ON CONFLICT DO NOTHING → status
tag "INSERT 0 0"), treats an identical-leaf replay as an idempotent success, and raises
`LedgerSequenceConflictError` for a differing entry so the `TrustLedger` rehydrates + retries. The
STH upsert is advance-only (a stale worker's late save with a smaller tree_size is skipped) —
same pattern as the witness state store.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import asyncpg

from quaicu.core.errors import LedgerPersistenceError, LedgerSequenceConflictError
from quaicu.core.ledger.signer import SignedTreeHead
from quaicu.core.types import ActionId, ActorId, ApproverRef, Decision, LedgerEntry, TenantId

# ── SQL ─────────────────────────────────────────────────────────────────────

_INSERT_ENTRY_SQL = """
INSERT INTO quaicu_ledger_entries
    (tenant_id, ledger_seq, action_id, action_type, actor_id, decision,
     policy_versions, leaf_hash, sealed_at, approver,
     consent_state, recorded_result, recorded_outputs, actor_roles)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
ON CONFLICT (tenant_id, ledger_seq) DO NOTHING
"""

_SELECT_ALL_ENTRIES_SQL = """
SELECT tenant_id, ledger_seq, action_id, action_type, actor_id, decision,
       policy_versions, leaf_hash, sealed_at, approver,
       consent_state, recorded_result, recorded_outputs, actor_roles
FROM   quaicu_ledger_entries
ORDER  BY tenant_id, ledger_seq
"""

_SELECT_TENANT_ENTRIES_SQL = """
SELECT tenant_id, ledger_seq, action_id, action_type, actor_id, decision,
       policy_versions, leaf_hash, sealed_at, approver,
       consent_state, recorded_result, recorded_outputs, actor_roles
FROM   quaicu_ledger_entries
WHERE  tenant_id = $1
ORDER  BY ledger_seq
"""

_SELECT_LEAF_AT_SEQ_SQL = """
SELECT leaf_hash FROM quaicu_ledger_entries WHERE tenant_id = $1 AND ledger_seq = $2
"""

# Advance-only: a stale worker's late save (smaller tree) can never regress the durable head.
# Equal sizes are allowed through so an idempotent replay refreshes nothing destructive (the
# winning root at a given size is already fixed by the entries PK).
_UPSERT_STH_SQL = """
INSERT INTO quaicu_ledger_sth
    (tenant_id, tree_size, root_hash, timestamp, signature, key_id)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (tenant_id) DO UPDATE SET
    tree_size = EXCLUDED.tree_size,
    root_hash = EXCLUDED.root_hash,
    timestamp = EXCLUDED.timestamp,
    signature = EXCLUDED.signature,
    key_id    = EXCLUDED.key_id
WHERE quaicu_ledger_sth.tree_size <= EXCLUDED.tree_size
"""

_SELECT_ALL_STH_SQL = """
SELECT tenant_id, tree_size, root_hash, timestamp, signature, key_id
FROM   quaicu_ledger_sth
"""


# ── JSONB helpers (asyncpg returns jsonb as text unless a codec is set) ─────────


def _loads_list(val: Any) -> list[Any]:
    if val is None:
        return []
    return json.loads(val) if isinstance(val, str) else list(val)


def _loads_dict(val: Any) -> dict[str, Any]:
    if val is None:
        return {}
    return json.loads(val) if isinstance(val, str) else dict(val)


# ── Row mappers ─────────────────────────────────────────────────────────────────


def _row_to_entry(row: asyncpg.Record) -> LedgerEntry:
    return LedgerEntry(
        ledger_seq=int(row["ledger_seq"]),
        tenant=TenantId(row["tenant_id"]),
        action_id=ActionId(row["action_id"]),
        action_type=row["action_type"],
        actor_id=ActorId(row["actor_id"]),
        decision=Decision(row["decision"]),
        policy_versions=tuple(_loads_list(row["policy_versions"])),
        leaf_hash=bytes(row["leaf_hash"]),
        sealed_at=row["sealed_at"],
        approver=ApproverRef(row["approver"]) if row["approver"] else None,
        consent_state=_loads_dict(row["consent_state"]),
        recorded_result=_loads_dict(row["recorded_result"]),
        recorded_outputs=_loads_dict(row["recorded_outputs"]),
        actor_roles=tuple(_loads_list(row["actor_roles"])),
    )


def _row_to_sth(row: asyncpg.Record) -> SignedTreeHead:
    return SignedTreeHead(
        tree_size=int(row["tree_size"]),
        timestamp=row["timestamp"],
        root_hash=bytes(row["root_hash"]),
        signature=bytes(row["signature"]),
        key_id=row["key_id"],
    )


# ── Adapter ───────────────────────────────────────────────────────────────────


class PostgresLedgerRepository:
    """Asyncpg-backed `LedgerRepository`. Pass a libpq/asyncpg DSN; pool is created lazily."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None
        self._pool_lock = asyncio.Lock()

    async def _get_pool(self) -> asyncpg.Pool:
        if self._pool is not None:
            return self._pool
        async with self._pool_lock:
            if self._pool is None:
                try:
                    # Bounded pool — shared SaaS plane runs several pools on one instance (see
                    # entitlements adapter). asyncpg's default (10) exhausts a small instance.
                    self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=4)
                except Exception as exc:
                    raise LedgerPersistenceError(
                        f"Failed to create Postgres pool: {exc}",
                        detail={"dsn_prefix": self._dsn[:30]},
                    ) from exc
        return self._pool  # type: ignore[return-value]

    # ── LedgerRepository ──────────────────────────────────────────────────────

    async def append_entry(self, entry: LedgerEntry) -> None:
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute("SELECT set_config('app.current_tenant', $1, true)", str(entry.tenant))
                    status = await conn.execute(
                        _INSERT_ENTRY_SQL,
                        str(entry.tenant),
                        entry.ledger_seq,
                        str(entry.action_id),
                        entry.action_type,
                        str(entry.actor_id),
                        entry.decision.value,
                        json.dumps(list(entry.policy_versions)),
                        bytes(entry.leaf_hash),
                        entry.sealed_at,
                        str(entry.approver) if entry.approver else None,
                        json.dumps(dict(entry.consent_state)),
                        json.dumps(dict(entry.recorded_result)),
                        json.dumps(dict(entry.recorded_outputs)),
                        json.dumps(list(entry.actor_roles)),
                    )
                    if status == "INSERT 0 0":
                        # ON CONFLICT DO NOTHING fired — another writer holds this seq. An
                        # identical leaf is an idempotent replay (success); a differing leaf
                        # means our in-memory tree is stale → typed conflict for retry.
                        stored = await conn.fetchval(
                            _SELECT_LEAF_AT_SEQ_SQL, str(entry.tenant), entry.ledger_seq
                        )
                        if stored is not None and bytes(stored) == bytes(entry.leaf_hash):
                            return
                        raise LedgerSequenceConflictError(
                            f"seq {entry.ledger_seq} for tenant {entry.tenant} already taken by a "
                            "different entry (concurrent seal from another worker)",
                            detail={"tenant": str(entry.tenant), "ledger_seq": entry.ledger_seq},
                        )
        except LedgerPersistenceError:
            raise
        except Exception as exc:
            raise LedgerPersistenceError(
                f"append_entry failed for {entry.tenant}@seq{entry.ledger_seq}: {exc}",
                detail={"tenant": str(entry.tenant), "ledger_seq": entry.ledger_seq},
            ) from exc

    async def load_entries(self) -> list[LedgerEntry]:
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                async with conn.transaction():
                    # Cross-tenant hydration read via the RLS read-only sentinel (migration 007):
                    # '*' matches every tenant in USING, but never in WITH CHECK, so this can read
                    # all rows but can't write across tenants. No DDL / ACCESS EXCLUSIVE lock.
                    await conn.execute("SELECT set_config('app.current_tenant', '*', true)")
                    rows = await conn.fetch(_SELECT_ALL_ENTRIES_SQL)
            return [_row_to_entry(r) for r in rows]
        except LedgerPersistenceError:
            raise
        except Exception as exc:
            raise LedgerPersistenceError(f"load_entries failed: {exc}") from exc

    async def load_tenant_entries(self, tenant: TenantId) -> list[LedgerEntry]:
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                async with conn.transaction():
                    # Tenant-scoped read — the tenant GUC satisfies RLS without the '*' sentinel.
                    await conn.execute(
                        "SELECT set_config('app.current_tenant', $1, true)", str(tenant)
                    )
                    rows = await conn.fetch(_SELECT_TENANT_ENTRIES_SQL, str(tenant))
            return [_row_to_entry(r) for r in rows]
        except LedgerPersistenceError:
            raise
        except Exception as exc:
            raise LedgerPersistenceError(
                f"load_tenant_entries failed for {tenant}: {exc}", detail={"tenant": str(tenant)}
            ) from exc

    async def save_sth(self, tenant: TenantId, sth: SignedTreeHead) -> None:
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute("SELECT set_config('app.current_tenant', $1, true)", str(tenant))
                    await conn.execute(
                        _UPSERT_STH_SQL,
                    str(tenant),
                    sth.tree_size,
                    bytes(sth.root_hash),
                    sth.timestamp,
                    bytes(sth.signature),
                    sth.key_id,
                )
        except LedgerPersistenceError:
            raise
        except Exception as exc:
            raise LedgerPersistenceError(
                f"save_sth failed for {tenant}: {exc}", detail={"tenant": str(tenant)}
            ) from exc

    async def load_sths(self) -> dict[str, SignedTreeHead]:
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                async with conn.transaction():
                    # Cross-tenant hydration read via the RLS read-only sentinel (migration 007).
                    await conn.execute("SELECT set_config('app.current_tenant', '*', true)")
                    rows = await conn.fetch(_SELECT_ALL_STH_SQL)
            return {r["tenant_id"]: _row_to_sth(r) for r in rows}
        except LedgerPersistenceError:
            raise
        except Exception as exc:
            raise LedgerPersistenceError(f"load_sths failed: {exc}") from exc

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
