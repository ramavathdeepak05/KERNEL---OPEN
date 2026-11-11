"""PostgresWrappedDekStore — durable home for KMS-wrapped DEKs (W6-4).

Implements `WrappedDekStore` (quaicu/adapters/erasure/gcp_kms) on psycopg2. Synchronous:
erasure/provisioning is off the hot path. Table `quaicu_shred_keys` (migration 012) is under FORCE RLS since migration 017 (D4-1): the
(tenant, subject)-keyed operations set the ``app.current_tenant`` GUC to the ref's tenant; only the
by-key_id ``get`` uses the ``'*'`` read-only sentinel (a key id precedes tenant knowledge). Only
KMS-**wrapped** DEKs are stored — the plaintext DEK is never persisted; ``destroy`` nulls the wrapped
blob and sets the tombstone so the subject can't resurrect.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from quaicu.core.erasure.keyring import SubjectRef
from quaicu.core.errors import ErasurePersistenceError

_PUT_SQL = """
INSERT INTO quaicu_shred_keys (tenant_id, subject_id, key_id, wrapped_dek, tombstoned, created_at)
VALUES (%s, %s, %s, %s, FALSE, now())
ON CONFLICT (tenant_id, subject_id) DO UPDATE SET
    key_id      = EXCLUDED.key_id,
    wrapped_dek = EXCLUDED.wrapped_dek,
    tombstoned  = FALSE
"""
_KEY_ID_FOR_SQL = (
    "SELECT key_id FROM quaicu_shred_keys "
    "WHERE tenant_id = %s AND subject_id = %s AND wrapped_dek IS NOT NULL"
)
_GET_SQL = "SELECT wrapped_dek FROM quaicu_shred_keys WHERE key_id = %s AND wrapped_dek IS NOT NULL"
_DELETE_SQL = (
    "UPDATE quaicu_shred_keys SET wrapped_dek = NULL, tombstoned = TRUE "
    "WHERE tenant_id = %s AND subject_id = %s AND wrapped_dek IS NOT NULL RETURNING key_id"
)
_TOMBSTONE_SQL = """
INSERT INTO quaicu_shred_keys (tenant_id, subject_id, key_id, wrapped_dek, tombstoned, created_at)
VALUES (%s, %s, '', NULL, TRUE, now())
ON CONFLICT (tenant_id, subject_id) DO UPDATE SET tombstoned = TRUE
"""
_IS_TOMBSTONED_SQL = "SELECT tombstoned FROM quaicu_shred_keys WHERE tenant_id = %s AND subject_id = %s"


class PostgresWrappedDekStore:
    """Sync psycopg2-backed `WrappedDekStore`. ``connect`` is injectable for tests."""

    def __init__(self, dsn: str, *, connect: Callable[[], Any] | None = None) -> None:
        self._dsn = dsn
        self._connect_fn = connect

    def _connect(self) -> Any:
        if self._connect_fn is not None:
            return self._connect_fn()
        import psycopg2  # lazy; already a dependency

        return psycopg2.connect(self._dsn)

    def _run(self, fn: Callable[[Any], Any], op: str, *, tenant: str = "*") -> Any:
        """One transaction with the RLS tenant GUC set (migration 017): the ref's tenant for
        (tenant, subject)-keyed operations, the '*' read-only sentinel for the by-key_id read."""
        try:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT set_config('app.current_tenant', %s, true)", (tenant,))
                    result = fn(cur)
                conn.commit()
                return result
            finally:
                conn.close()
        except ErasurePersistenceError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ErasurePersistenceError(f"shred-key {op} failed: {exc}") from exc

    def key_id_for(self, ref: SubjectRef) -> str | None:
        def _q(cur: Any) -> str | None:
            cur.execute(_KEY_ID_FOR_SQL, (ref[0], ref[1]))
            row = cur.fetchone()
            return row[0] if row else None

        return self._run(_q, "key_id_for", tenant=str(ref[0]))

    def get(self, key_id: str) -> bytes | None:
        def _q(cur: Any) -> bytes | None:
            cur.execute(_GET_SQL, (key_id,))
            row = cur.fetchone()
            return bytes(row[0]) if row and row[0] is not None else None

        return self._run(_q, "get")

    def put(self, ref: SubjectRef, key_id: str, wrapped: bytes) -> None:
        self._run(
            lambda cur: cur.execute(_PUT_SQL, (ref[0], ref[1], key_id, wrapped)),
            "put",
            tenant=str(ref[0]),
        )

    def delete(self, ref: SubjectRef) -> str | None:
        def _d(cur: Any) -> str | None:
            cur.execute(_DELETE_SQL, (ref[0], ref[1]))
            row = cur.fetchone()
            return row[0] if row else None

        return self._run(_d, "delete", tenant=str(ref[0]))

    def tombstone(self, ref: SubjectRef) -> None:
        self._run(
            lambda cur: cur.execute(_TOMBSTONE_SQL, (ref[0], ref[1])),
            "tombstone",
            tenant=str(ref[0]),
        )

    def is_tombstoned(self, ref: SubjectRef) -> bool:
        def _q(cur: Any) -> bool:
            cur.execute(_IS_TOMBSTONED_SQL, (ref[0], ref[1]))
            row = cur.fetchone()
            return bool(row[0]) if row else False

        return self._run(_q, "is_tombstoned", tenant=str(ref[0]))
