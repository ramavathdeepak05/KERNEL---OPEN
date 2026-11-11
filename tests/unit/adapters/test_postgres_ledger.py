"""Unit tests for PostgresLedgerRepository — no real database required.

All asyncpg calls are patched with AsyncMock (mirrors test_postgres_policy.py) so these run in the
standard pytest-asyncio suite without any external services.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from quaicu.adapters.ledger.postgres import PostgresLedgerRepository, _row_to_entry, _row_to_sth
from quaicu.core.errors import LedgerPersistenceError
from quaicu.core.ledger.signer import SignedTreeHead
from quaicu.core.types import (
    ActionId,
    ActorId,
    ApproverRef,
    Decision,
    LedgerEntry,
    TenantId,
)

NOW = datetime(2026, 6, 12, 12, 0, tzinfo=timezone.utc)


def _fake_pool(conn: AsyncMock) -> MagicMock:
    # The repo opens a transaction to set the RLS tenant context (app.current_tenant) / toggle
    # row_security for hydration reads, so conn.transaction() must be an async context manager.
    conn.transaction = MagicMock()
    conn.transaction.return_value.__aenter__ = AsyncMock(return_value=None)
    conn.transaction.return_value.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire_cm)
    return pool


def _entry() -> LedgerEntry:
    return LedgerEntry(
        ledger_seq=3,
        tenant=TenantId("acme"),
        action_id=ActionId("act-1"),
        action_type="payments.wire",
        actor_id=ActorId("alice"),
        decision=Decision.ALLOW,
        policy_versions=("p@v1",),
        leaf_hash=b"\x11" * 32,
        sealed_at=NOW,
        approver=ApproverRef("user:risk-officer"),
        consent_state={"purpose": "kyc"},
        recorded_result={"ok": True},
        recorded_outputs={"score": 0.9},
        actor_roles=("role:maker",),
    )


def _sth() -> SignedTreeHead:
    return SignedTreeHead(
        tree_size=4, timestamp=NOW, root_hash=b"\x22" * 32, signature=b"sig", key_id="k:v1"
    )


# ── Row mappers ──────────────────────────────────────────────────────────────────


def test_row_to_entry_round_trip() -> None:
    row = {
        "tenant_id": "acme", "ledger_seq": 3, "action_id": "act-1",
        "action_type": "payments.wire", "actor_id": "alice", "decision": "allow",
        "policy_versions": '["p@v1"]', "leaf_hash": b"\x11" * 32, "sealed_at": NOW,
        "approver": "user:risk-officer", "consent_state": '{"purpose": "kyc"}',
        "recorded_result": '{"ok": true}', "recorded_outputs": '{"score": 0.9}',
        "actor_roles": '["role:maker"]',
    }
    e = _row_to_entry(row)
    assert e.ledger_seq == 3
    assert e.tenant == TenantId("acme")
    assert e.decision is Decision.ALLOW
    assert e.policy_versions == ("p@v1",)
    assert e.leaf_hash == b"\x11" * 32
    assert e.approver == ApproverRef("user:risk-officer")
    assert e.actor_roles == ("role:maker",)
    assert e.recorded_outputs == {"score": 0.9}


def test_row_to_entry_null_approver() -> None:
    row = {
        "tenant_id": "acme", "ledger_seq": 0, "action_id": "a", "action_type": "t",
        "actor_id": "x", "decision": "deny", "policy_versions": "[]",
        "leaf_hash": b"\x00" * 32, "sealed_at": NOW, "approver": None,
        "consent_state": "{}", "recorded_result": "{}", "recorded_outputs": "{}",
        "actor_roles": "[]",
    }
    assert _row_to_entry(row).approver is None


def test_row_to_sth_round_trip() -> None:
    row = {
        "tenant_id": "acme", "tree_size": 4, "root_hash": b"\x22" * 32,
        "timestamp": NOW, "signature": b"sig", "key_id": "k:v1",
    }
    s = _row_to_sth(row)
    assert s.tree_size == 4
    assert s.root_hash == b"\x22" * 32
    assert s.signature == b"sig"


# ── append_entry ─────────────────────────────────────────────────────────────────


async def test_append_entry_executes_insert() -> None:
    conn = AsyncMock()
    conn.execute = AsyncMock(return_value="INSERT 0 1")
    repo = PostgresLedgerRepository(dsn="postgresql://fake/fake")
    repo._pool = _fake_pool(conn)

    await repo.append_entry(_entry())
    # Two executes now: set_config('app.current_tenant', …) then the insert. await_args is the last
    # call (the insert), so the column assertions below validate the insert payload.
    assert conn.execute.await_count == 2
    args = conn.execute.await_args.args
    assert args[1] == "acme"  # tenant_id
    assert args[2] == 3  # ledger_seq
    assert args[6] == "allow"  # decision
    assert args[8] == b"\x11" * 32  # leaf_hash (bytea passthrough)
    assert args[10] == "user:risk-officer"  # approver


async def test_append_entry_wraps_errors() -> None:
    conn = AsyncMock()
    conn.execute = AsyncMock(side_effect=Exception("db down"))
    repo = PostgresLedgerRepository(dsn="postgresql://fake/fake")
    repo._pool = _fake_pool(conn)

    with pytest.raises(LedgerPersistenceError):
        await repo.append_entry(_entry())


# ── save_sth / load ──────────────────────────────────────────────────────────────


async def test_save_sth_executes_upsert() -> None:
    conn = AsyncMock()
    conn.execute = AsyncMock(return_value="INSERT 0 1")
    repo = PostgresLedgerRepository(dsn="postgresql://fake/fake")
    repo._pool = _fake_pool(conn)

    await repo.save_sth(TenantId("acme"), _sth())
    args = conn.execute.await_args.args
    assert args[1] == "acme"
    assert args[2] == 4  # tree_size
    assert args[3] == b"\x22" * 32  # root_hash


async def test_load_entries_maps_rows() -> None:
    row = {
        "tenant_id": "acme", "ledger_seq": 0, "action_id": "a", "action_type": "t",
        "actor_id": "x", "decision": "allow", "policy_versions": "[]",
        "leaf_hash": b"\x00" * 32, "sealed_at": NOW, "approver": None,
        "consent_state": "{}", "recorded_result": "{}", "recorded_outputs": "{}",
        "actor_roles": "[]",
    }
    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=[row])
    repo = PostgresLedgerRepository(dsn="postgresql://fake/fake")
    repo._pool = _fake_pool(conn)

    entries = await repo.load_entries()
    assert len(entries) == 1 and entries[0].action_type == "t"


async def test_load_sths_keyed_by_tenant() -> None:
    row = {
        "tenant_id": "acme", "tree_size": 4, "root_hash": b"\x22" * 32,
        "timestamp": NOW, "signature": b"sig", "key_id": "k:v1",
    }
    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=[row])
    repo = PostgresLedgerRepository(dsn="postgresql://fake/fake")
    repo._pool = _fake_pool(conn)

    sths = await repo.load_sths()
    assert "acme" in sths and sths["acme"].tree_size == 4


async def test_load_entries_wraps_errors() -> None:
    conn = AsyncMock()
    conn.fetch = AsyncMock(side_effect=Exception("db down"))
    repo = PostgresLedgerRepository(dsn="postgresql://fake/fake")
    repo._pool = _fake_pool(conn)

    with pytest.raises(LedgerPersistenceError):
        await repo.load_entries()
