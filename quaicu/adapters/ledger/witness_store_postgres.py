"""PostgresWitnessStateStore — durable, monotonic witness last-seen store (D3-2 follow-up).

Satisfies `core.ledger.anchor.WitnessStateStore`. Persists the last STH the anchor witness cosigned
per tenant to ``quaicu_witness_state`` (migration 016), so the witness's rewind detection survives a
restart and is consistent across replicas. Advance is **monotonic at the SQL level**: the conditional
upsert only accepts a ``tree_size`` at or above the stored one, so a smaller (rewound) size can never
overwrite the stored high-water mark — defence-in-depth on top of the witness's own consistency check.

Synchronous (psycopg2, already a dependency), mirroring `adapters/hitl/postgres_store.py`. Cosign is
low-frequency (export + periodic anchor), not a per-action hot path, so the blocking call is fine.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from quaicu.core.types import TenantId

_UPSERT_SQL = (
    "INSERT INTO quaicu_witness_state (tenant_id, tree_size, root_hash, updated_at) "
    "VALUES (%s, %s, %s, now()) "
    "ON CONFLICT (tenant_id) DO UPDATE SET "
    "tree_size = EXCLUDED.tree_size, root_hash = EXCLUDED.root_hash, updated_at = now() "
    "WHERE EXCLUDED.tree_size >= quaicu_witness_state.tree_size"
)
_SELECT_SQL = "SELECT tree_size, root_hash FROM quaicu_witness_state WHERE tenant_id = %s"


class PostgresWitnessStateStore:
    """Durable witness state store. ``connect`` is injectable for tests (a fake conn factory)."""

    def __init__(self, dsn: str, *, connect: Callable[[], Any] | None = None) -> None:
        self._dsn = dsn
        self._connect_fn = connect

    def _connect(self) -> Any:
        if self._connect_fn is not None:
            return self._connect_fn()
        import psycopg2  # lazy; already a dependency

        return psycopg2.connect(self._dsn)

    def _run(self, fn: Callable[[Any], Any]) -> Any:
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                result = fn(cur)
            conn.commit()
            return result
        finally:
            conn.close()

    def get(self, tenant: TenantId) -> tuple[int, bytes] | None:
        def _q(cur: Any) -> tuple[int, bytes] | None:
            cur.execute(_SELECT_SQL, (str(tenant),))
            row = cur.fetchone()
            return (int(row[0]), bytes(row[1])) if row else None

        return self._run(_q)

    def advance(self, tenant: TenantId, tree_size: int, root_hash: bytes) -> None:
        import psycopg2  # for Binary; lazy

        self._run(
            lambda cur: cur.execute(
                _UPSERT_SQL, (str(tenant), tree_size, psycopg2.Binary(root_hash))
            )
        )
