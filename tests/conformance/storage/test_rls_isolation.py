"""Adversarial RLS tenant-isolation proofs against a real Postgres (D4-1, F-07).

For EVERY tenant-keyed kernel table (the 3 from migrations 004/007 + the 2 from 017), prove at the
database layer — independent of any adapter WHERE clause — that a session scoped to tenant A:

  - cannot SELECT tenant B's rows (and sees ONLY tenant A rows at all),
  - cannot UPDATE or DELETE tenant B's rows (0 rows affected),
  - cannot INSERT a row tagged with tenant B (policy violation),

that a session with NO tenant GUC sees nothing (deny-by-default), that the internal ``'*'``
hydration sentinel reads across tenants but cannot WRITE (migration 007 semantics), and that
FORCE RLS is actually on (`pg_class.relforcerowsecurity`) so even the table owner is filtered.

Skipped unless ``DATABASE_URL`` is set (run ``alembic upgrade head`` — needs migration 017):

    DATABASE_URL=postgresql://quaicu:quaicu-dev@127.0.0.1:5433/quaicu?sslmode=disable \\
        pytest tests/conformance/storage/test_rls_isolation.py -m integration -v
"""

from __future__ import annotations

import os

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
skip_no_db = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set — skipping integration tests"
)

TENANT_A = "test-iso-a"
TENANT_B = "test-iso-b"

# Per-table minimal INSERT: $1 = tenant_id; remaining literals derive from the tenant so the two
# seeded rows are unique across every PK/unique constraint.
_SPECS: dict[str, str] = {
    "quaicu_actions": (
        "INSERT INTO quaicu_actions (id, tenant_id, idempotency_key, type, state, actor_id, "
        "actor_tenant, proposed_at) VALUES ('act-' || $1, $1, 'ik-' || $1, 'iso.test', "
        "'PROPOSED', 'alice', $1, now())"
    ),
    "quaicu_ledger_entries": (
        "INSERT INTO quaicu_ledger_entries (tenant_id, ledger_seq, action_id, action_type, "
        "actor_id, decision, leaf_hash, sealed_at) VALUES ($1, 0, 'act-' || $1, 'iso.test', "
        "'alice', 'allow', '\\x00'::bytea, now())"
    ),
    "quaicu_ledger_sth": (
        "INSERT INTO quaicu_ledger_sth (tenant_id, tree_size, root_hash, timestamp, signature, "
        "key_id) VALUES ($1, 1, '\\x00'::bytea, now(), '\\x00'::bytea, 'k-iso')"
    ),
    "quaicu_shred_keys": (
        "INSERT INTO quaicu_shred_keys (tenant_id, subject_id, key_id) "
        "VALUES ($1, 'subj-1', 'sk-' || $1)"
    ),
    "quaicu_approvals": (
        "INSERT INTO quaicu_approvals (handle_id, action_id, tenant_id, requested_at) "
        "VALUES ('test-h-' || $1, 'act-' || $1, $1, now())"
    ),
}

ALL_TABLES = tuple(_SPECS)


async def _connect():
    import asyncpg

    return await asyncpg.connect(DATABASE_URL)


async def _set_tenant(conn, tenant: str | None) -> None:
    # Transaction-local GUC, exactly as the adapters set it. None = leave unset (deny-by-default).
    if tenant is not None:
        await conn.execute("SELECT set_config('app.current_tenant', $1, true)", tenant)


async def _wipe() -> None:
    """Delete both test tenants' rows everywhere, bypassing RLS via the owner NO FORCE toggle
    (test-% ids only)."""
    conn = await _connect()
    try:
        async with conn.transaction():
            for table in ALL_TABLES:
                await conn.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
            await conn.execute("SET LOCAL row_security = off")
            for table in ALL_TABLES:
                await conn.execute(
                    f"DELETE FROM {table} WHERE tenant_id IN ($1, $2)", TENANT_A, TENANT_B
                )
            for table in ALL_TABLES:
                await conn.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    finally:
        await conn.close()


async def _seed(table: str) -> None:
    """Insert one row per tenant, each under its own GUC (the legitimate write path)."""
    conn = await _connect()
    try:
        for tenant in (TENANT_A, TENANT_B):
            async with conn.transaction():
                await _set_tenant(conn, tenant)
                await conn.execute(_SPECS[table], tenant)
    finally:
        await conn.close()


@pytest.fixture
async def clean():
    await _wipe()
    yield
    await _wipe()


@pytest.mark.integration
@skip_no_db
@pytest.mark.parametrize("table", ALL_TABLES)
async def test_tenant_a_cannot_touch_tenant_b(table: str, clean) -> None:
    await _seed(table)
    conn = await _connect()
    try:
        # SELECT: A sees no B rows, and everything visible IS A's.
        async with conn.transaction():
            await _set_tenant(conn, TENANT_A)
            b_visible = await conn.fetchval(
                f"SELECT count(*) FROM {table} WHERE tenant_id = $1", TENANT_B
            )
            foreign = await conn.fetchval(
                f"SELECT count(*) FROM {table} WHERE tenant_id <> $1", TENANT_A
            )
            own = await conn.fetchval(
                f"SELECT count(*) FROM {table} WHERE tenant_id = $1", TENANT_A
            )
        assert b_visible == 0, f"{table}: tenant A can read tenant B rows"
        assert foreign == 0, f"{table}: tenant A sees foreign rows"
        assert own == 1, f"{table}: tenant A cannot read its own row"

        # UPDATE / DELETE targeting B: 0 rows affected (B's rows are invisible to the policy).
        async with conn.transaction():
            await _set_tenant(conn, TENANT_A)
            updated = await conn.execute(
                f"UPDATE {table} SET tenant_id = tenant_id WHERE tenant_id = $1", TENANT_B
            )
            deleted = await conn.execute(f"DELETE FROM {table} WHERE tenant_id = $1", TENANT_B)
        assert updated.endswith(" 0"), f"{table}: tenant A updated tenant B rows"
        assert deleted.endswith(" 0"), f"{table}: tenant A deleted tenant B rows"
    finally:
        await conn.close()


@pytest.mark.integration
@skip_no_db
@pytest.mark.parametrize("table", ALL_TABLES)
async def test_cross_tenant_insert_rejected(table: str, clean) -> None:
    """A session scoped to A cannot forge a row tagged B (WITH CHECK)."""
    import asyncpg

    conn = await _connect()
    try:
        with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
            async with conn.transaction():
                await _set_tenant(conn, TENANT_A)
                await conn.execute(_SPECS[table], TENANT_B)
    finally:
        await conn.close()


@pytest.mark.integration
@skip_no_db
@pytest.mark.parametrize("table", ALL_TABLES)
async def test_no_guc_sees_nothing(table: str, clean) -> None:
    """Deny-by-default: a connection that never set a tenant reads zero rows."""
    await _seed(table)
    conn = await _connect()
    try:
        async with conn.transaction():
            visible = await conn.fetchval(f"SELECT count(*) FROM {table}")
        assert visible == 0, f"{table}: un-scoped session can read rows"
    finally:
        await conn.close()


@pytest.mark.integration
@skip_no_db
@pytest.mark.parametrize("table", ALL_TABLES)
async def test_sentinel_reads_all_but_cannot_write(table: str, clean) -> None:
    """The '*' hydration sentinel reads across tenants (migration 007) but any write is rejected."""
    import asyncpg

    await _seed(table)
    conn = await _connect()
    try:
        async with conn.transaction():
            await _set_tenant(conn, "*")
            both = await conn.fetchval(
                f"SELECT count(*) FROM {table} WHERE tenant_id IN ($1, $2)", TENANT_A, TENANT_B
            )
        assert both == 2, f"{table}: sentinel read is broken"

        with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
            async with conn.transaction():
                await _set_tenant(conn, "*")
                await conn.execute(_SPECS[table], "test-iso-c")
    finally:
        await conn.close()


@pytest.mark.integration
@skip_no_db
async def test_force_rls_active_on_every_table() -> None:
    """FORCE RLS on: even the owning role is filtered — no bypass via ownership."""
    conn = await _connect()
    try:
        rows = await conn.fetch(
            "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE relname = ANY($1::text[])",
            list(ALL_TABLES),
        )
        by_name = {r["relname"]: r for r in rows}
        assert set(by_name) == set(ALL_TABLES), "missing table(s) in pg_class lookup"
        for table, r in by_name.items():
            assert r["relrowsecurity"], f"{table}: RLS not enabled"
            assert r["relforcerowsecurity"], f"{table}: RLS not FORCEd"
    finally:
        await conn.close()


@pytest.mark.integration
@skip_no_db
async def test_ledger_repo_end_to_end_isolation(clean) -> None:
    """Through the real adapter: tenant A's ledger writes are invisible to a B-scoped session."""
    from datetime import datetime, timezone

    from quaicu.adapters.ledger.postgres import PostgresLedgerRepository
    from quaicu.core.types import ActionId, ActorId, Decision, LedgerEntry, TenantId

    repo = PostgresLedgerRepository(dsn=DATABASE_URL)
    try:
        await repo.append_entry(
            LedgerEntry(
                ledger_seq=0,
                tenant=TenantId(TENANT_A),
                action_id=ActionId("act-e2e"),
                action_type="iso.test",
                actor_id=ActorId("alice"),
                decision=Decision.ALLOW,
                policy_versions=(),
                leaf_hash=b"\x01" * 32,
                sealed_at=datetime.now(tz=timezone.utc),
            )
        )
        # Adapter-level tenant-scoped read sees it…
        assert len(await repo.load_tenant_entries(TenantId(TENANT_A))) == 1
        # …but a raw session scoped to B cannot, regardless of any WHERE clause.
        conn = await _connect()
        try:
            async with conn.transaction():
                await _set_tenant(conn, TENANT_B)
                stolen = await conn.fetchval(
                    "SELECT count(*) FROM quaicu_ledger_entries WHERE tenant_id = $1", TENANT_A
                )
            assert stolen == 0
        finally:
            await conn.close()
    finally:
        await repo.close()
