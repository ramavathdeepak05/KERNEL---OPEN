"""PostgresApprovalStore — durable, psycopg2-backed HITL approval store.

Drop-in replacement for the in-memory ``core.hitl.store.ApprovalStore`` (same sync surface:
``put`` / ``get`` / ``update`` / ``get_by_action`` / ``pending_count`` / ``list_pending``), injected into
``InProcessHITLPort(store=...)``. Makes the ``/v1/approvals`` queue **consistent across Cloud Run
instances** — the in-memory store is per-process, so a horizontally-scaled service shows an inconsistent
queue; this persists it to ``quaicu_approvals``.

**Synchronous** (psycopg2, already a dependency — alembic + the account adapter use it). HITL store
operations happen on the gate (a ``require_approval`` action) and on approvals list/decide — low
frequency, not the per-action hot path — so the blocking call is acceptable, matching the sync
``PostgresAccountRepository`` precedent.

Since migration 017 (D4-1) ``quaicu_approvals`` is under FORCE RLS, so every operation sets the
``app.current_tenant`` GUC for its transaction: writes use the record's tenant; the by-handle /
by-action reads and the queue reads use the ``'*'`` read-only sentinel (a handle id precedes tenant
knowledge, and ``list_pending`` / ``pending_count`` are intentionally cross-tenant for the operator
queue — the route still filters by the request tenant and rejects deciding another tenant's
approval with 403, exactly as before; the sentinel cannot write).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from quaicu.core.hitl.model import ApprovalRecord
from quaicu.core.types import ActionId, ActorId, ApprovalDecision, ApproverRef, TenantId

_COLS = (
    "handle_id, action_id, tenant_id, required_approvers, requested_at, decision, "
    "decided_by, decided_at, expires_at, proposed_by, notify_channel, notify_target, resume_link"
)
_INSERT_SQL = (
    f"INSERT INTO quaicu_approvals ({_COLS}) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
    "ON CONFLICT (handle_id) DO UPDATE SET "
    "decision = EXCLUDED.decision, decided_by = EXCLUDED.decided_by, "
    "decided_at = EXCLUDED.decided_at, expires_at = EXCLUDED.expires_at"
)
_SELECT_SQL = f"SELECT {_COLS} FROM quaicu_approvals"
_UPDATE_SQL = (
    "UPDATE quaicu_approvals SET decision = %s, decided_by = %s, decided_at = %s, expires_at = %s "
    "WHERE handle_id = %s"
)


def _row_to_record(r: tuple) -> ApprovalRecord:
    return ApprovalRecord(
        handle_id=r[0],
        action_id=ActionId(r[1]),
        tenant=TenantId(r[2]),
        required_approvers=tuple(ApproverRef(a) for a in (json.loads(r[3]) if r[3] else [])),
        requested_at=r[4],
        decision=ApprovalDecision(r[5]),
        decided_by=ActorId(r[6]) if r[6] else None,
        decided_at=r[7],
        expires_at=r[8],
        proposed_by=ActorId(r[9]) if r[9] else None,
        notify_channel=r[10],
        notify_target=r[11],
        resume_link=r[12],
    )


def _params(rec: ApprovalRecord) -> tuple:
    return (
        rec.handle_id,
        str(rec.action_id),
        str(rec.tenant),
        json.dumps([str(a) for a in rec.required_approvers]),
        rec.requested_at,
        rec.decision.value,
        str(rec.decided_by) if rec.decided_by else None,
        rec.decided_at,
        rec.expires_at,
        str(rec.proposed_by) if rec.proposed_by else None,
        rec.notify_channel,
        rec.notify_target,
        rec.resume_link,
    )


class PostgresApprovalStore:
    """Durable HITL approval store. ``connect`` is injectable for tests (a fake conn factory)."""

    def __init__(self, dsn: str, *, connect: Callable[[], Any] | None = None) -> None:
        self._dsn = dsn
        self._connect_fn = connect

    def _connect(self) -> Any:
        if self._connect_fn is not None:
            return self._connect_fn()
        import psycopg2  # lazy; already a dependency (alembic + account adapter)

        return psycopg2.connect(self._dsn)

    def _run(self, fn: Callable[[Any], Any], *, tenant: str = "*") -> Any:
        """One transaction with the RLS tenant GUC set (migration 017): owning tenant for writes,
        the '*' read-only sentinel for by-handle / cross-tenant queue reads."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT set_config('app.current_tenant', %s, true)", (tenant,))
                result = fn(cur)
            conn.commit()
            return result
        finally:
            conn.close()

    # ── ApprovalStore surface ──────────────────────────────────────────────────

    def put(self, record: ApprovalRecord) -> None:
        self._run(
            lambda cur: cur.execute(_INSERT_SQL, _params(record)), tenant=str(record.tenant)
        )

    def get(self, handle_id: str) -> ApprovalRecord | None:
        def _q(cur: Any) -> ApprovalRecord | None:
            cur.execute(f"{_SELECT_SQL} WHERE handle_id = %s", (handle_id,))
            row = cur.fetchone()
            return _row_to_record(row) if row else None

        return self._run(_q)

    def update(self, record: ApprovalRecord) -> None:
        def _u(cur: Any) -> None:
            cur.execute(
                _UPDATE_SQL,
                (
                    record.decision.value,
                    str(record.decided_by) if record.decided_by else None,
                    record.decided_at,
                    record.expires_at,
                    record.handle_id,
                ),
            )
            if cur.rowcount == 0:
                raise KeyError(f"Handle {record.handle_id!r} not in store.")

        self._run(_u, tenant=str(record.tenant))

    def get_by_action(self, action_id: ActionId) -> ApprovalRecord | None:
        def _q(cur: Any) -> ApprovalRecord | None:
            cur.execute(f"{_SELECT_SQL} WHERE action_id = %s", (str(action_id),))
            row = cur.fetchone()
            return _row_to_record(row) if row else None

        return self._run(_q)

    def pending_count(self) -> int:
        def _q(cur: Any) -> int:
            cur.execute("SELECT count(*) FROM quaicu_approvals WHERE decision = %s", ("PENDING",))
            return int(cur.fetchone()[0])

        return self._run(_q)

    def list_pending(self) -> list[ApprovalRecord]:
        def _q(cur: Any) -> list[ApprovalRecord]:
            cur.execute(f"{_SELECT_SQL} WHERE decision = %s ORDER BY requested_at", ("PENDING",))
            return [_row_to_record(r) for r in cur.fetchall()]

        return self._run(_q)
