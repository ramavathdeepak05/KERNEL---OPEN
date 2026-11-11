"""PostgresApprovalStore — durable HITL queue, no real DB (fake psycopg2 conn/cursor).

Covers the round-trip fidelity of an ApprovalRecord through `_params`/`_row_to_record` and the store's
put/get/update/list_pending/get_by_action behavior (incl. KeyError on update-missing, matching the
in-memory ApprovalStore contract).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quaicu.adapters.hitl.postgres_store import PostgresApprovalStore, _params, _row_to_record
from quaicu.core.hitl.model import ApprovalRecord
from quaicu.core.types import ActionId, ActorId, ApprovalDecision, ApproverRef, TenantId

NOW = datetime(2026, 6, 25, 12, 0, tzinfo=timezone.utc)


def _record(decision: ApprovalDecision = ApprovalDecision.PENDING) -> ApprovalRecord:
    return ApprovalRecord(
        handle_id="h-1",
        action_id=ActionId("act-1"),
        tenant=TenantId("acme"),
        required_approvers=(ApproverRef("role:compliance"), ApproverRef("role:cro")),
        requested_at=NOW,
        decision=decision,
        decided_by=ActorId("risk_head") if decision is not ApprovalDecision.PENDING else None,
        proposed_by=ActorId("agent:underwriter"),
    )


class _FakeCursor:
    def __init__(self, rows: list[tuple], rowcount: int = 1) -> None:
        self._rows = rows
        self.rowcount = rowcount
        self.executed: list[tuple] = []

    def __enter__(self):  # noqa: ANN204
        return self

    def __exit__(self, *a) -> bool:  # noqa: ANN002
        return False

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.executed.append((sql, params))

    def fetchone(self):  # noqa: ANN201
        return self._rows[0] if self._rows else None

    def fetchall(self):  # noqa: ANN201
        return list(self._rows)


class _FakeConn:
    def __init__(self, cur: _FakeCursor) -> None:
        self._cur = cur
        self.committed = False

    def cursor(self) -> _FakeCursor:
        return self._cur

    def commit(self) -> None:
        self.committed = True

    def close(self) -> None:
        pass


def _store(cur: _FakeCursor) -> PostgresApprovalStore:
    return PostgresApprovalStore("dsn://ignored", connect=lambda: _FakeConn(cur))


def test_params_row_roundtrip() -> None:
    rec = _record(ApprovalDecision.APPROVED)
    # _params produces values in the same column order _row_to_record reads → a faithful round-trip.
    restored = _row_to_record(_params(rec))
    assert restored == rec


def test_put_then_get() -> None:
    rec = _record()
    put_cur = _FakeCursor(rows=[])
    _store(put_cur).put(rec)
    # First statement sets the RLS tenant GUC (migration 017) with the record's tenant; then the insert.
    assert "set_config('app.current_tenant'" in put_cur.executed[0][0]
    assert put_cur.executed[0][1] == ("acme",)
    assert "INSERT INTO quaicu_approvals" in put_cur.executed[1][0]

    get_cur = _FakeCursor(rows=[_params(rec)])
    got = _store(get_cur).get("h-1")
    assert got == rec


def test_get_missing_returns_none() -> None:
    assert _store(_FakeCursor(rows=[])).get("nope") is None


def test_update_missing_raises_keyerror() -> None:
    with pytest.raises(KeyError):
        _store(_FakeCursor(rows=[], rowcount=0)).update(_record(ApprovalDecision.APPROVED))


def test_list_pending_and_count() -> None:
    rows = [_params(_record()), _params(_record())]
    assert len(_store(_FakeCursor(rows=rows)).list_pending()) == 2
    assert _store(_FakeCursor(rows=[(2,)])).pending_count() == 2


def test_get_by_action() -> None:
    rec = _record()
    got = _store(_FakeCursor(rows=[_params(rec)])).get_by_action(ActionId("act-1"))
    assert got == rec
