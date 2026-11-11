"""Unit tests for the WS-E tenant-isolation primitives + provisioner (F-07)."""

from __future__ import annotations

import pytest

from quaicu.adapters.storage.isolation import (
    assert_safe_tenant,
    current_db_tenant,
    db_tenant_scope,
    create_tenant_schema_sql,
    drop_tenant_schema_sql,
    safe_schema_name,
    search_path_sql,
    set_rls_tenant_sql,
)
from quaicu.adapters.storage.provisioner import (
    TenantProvisioner,
    offboard_statements,
    onboard_statements,
)
from quaicu.core.errors import StoragePortError, TenantIsolationError
from quaicu.core.types import TenantId


# ── Safe identifier derivation (fail-closed) ─────────────────────────────────────


def test_safe_schema_name_maps_hyphens():
    assert safe_schema_name(TenantId("acme-co-1a2b3c")) == "tenant_acme_co_1a2b3c"


def test_safe_schema_name_custom_prefix():
    assert safe_schema_name("biz", prefix="t_") == "t_biz"


@pytest.mark.parametrize(
    "evil",
    [
        'acme"; DROP SCHEMA public; --',
        "acme co",          # space
        "acme;co",          # semicolon
        "ACME",             # uppercase not allowed
        "-acme",            # must start alphanumeric
        "",                 # empty
        "a" * 80,           # too long for a 63-byte identifier
    ],
)
def test_unsafe_tenant_ids_rejected(evil):
    with pytest.raises(TenantIsolationError):
        assert_safe_tenant(evil)
    with pytest.raises(TenantIsolationError):
        safe_schema_name(evil)


def test_assert_safe_tenant_returns_value():
    assert assert_safe_tenant("acme-co") == "acme-co"


# ── SQL builders ─────────────────────────────────────────────────────────────────


def test_search_path_sql_quotes_schema():
    sql = search_path_sql(TenantId("acme-co"))
    assert sql == 'SET LOCAL search_path TO "tenant_acme_co", public'


def test_create_and_drop_schema_sql():
    assert create_tenant_schema_sql("acme-co") == 'CREATE SCHEMA IF NOT EXISTS "tenant_acme_co"'
    assert drop_tenant_schema_sql("acme-co") == 'DROP SCHEMA IF EXISTS "tenant_acme_co" CASCADE'


def test_rls_set_tenant_sql_is_parameterized():
    # The tenant id must be a bind parameter ($1), never interpolated.
    sql = set_rls_tenant_sql()
    assert "$1" in sql
    assert "set_config" in sql
    assert "app.current_tenant" in sql


# ── RLS tenant ContextVar ────────────────────────────────────────────────────────


def test_db_tenant_scope_sets_and_restores():
    assert current_db_tenant.get() is None
    with db_tenant_scope("acme-co"):
        assert current_db_tenant.get() == "acme-co"
        with db_tenant_scope("other-co"):
            assert current_db_tenant.get() == "other-co"
        assert current_db_tenant.get() == "acme-co"  # nested scope restored
    assert current_db_tenant.get() is None


def test_db_tenant_scope_rejects_unsafe_tenant():
    with pytest.raises(TenantIsolationError):
        with db_tenant_scope("evil; DROP"):
            pass


# ── Provisioner statement generation ─────────────────────────────────────────────


def test_onboard_statements_order_and_content():
    stmts = onboard_statements("acme-co")
    assert stmts[0] == 'CREATE SCHEMA IF NOT EXISTS "tenant_acme_co"'
    assert stmts[1] == 'SET LOCAL search_path TO "tenant_acme_co", public'
    body = "\n".join(stmts[2:])
    assert "quaicu_actions" in body
    assert "quaicu_ledger_entries" in body
    assert "quaicu_ledger_sth" in body


def test_offboard_statements():
    assert offboard_statements("acme-co") == ['DROP SCHEMA IF EXISTS "tenant_acme_co" CASCADE']


# ── Provisioner execution (mocked asyncpg pool) ──────────────────────────────────


class _FakeConn:
    def __init__(self, record: list[str]) -> None:
        self._record = record

    def transaction(self):
        conn = self

        class _Txn:
            async def __aenter__(self_):  # noqa: N805
                return conn

            async def __aexit__(self_, *exc):  # noqa: N805
                return False

        return _Txn()

    async def execute(self, sql: str) -> None:
        self._record.append(sql)


class _FakePool:
    def __init__(self, *, fail: bool = False) -> None:
        self.executed: list[str] = []
        self._fail = fail

    def acquire(self):
        pool = self

        class _Acq:
            async def __aenter__(self_):  # noqa: N805
                if pool._fail:
                    raise RuntimeError("db down")
                return _FakeConn(pool.executed)

            async def __aexit__(self_, *exc):  # noqa: N805
                return False

        return _Acq()


async def test_provisioner_onboard_executes_statements():
    pool = _FakePool()
    provisioner = TenantProvisioner(pool)
    schema = await provisioner.onboard("acme-co")
    assert schema == "tenant_acme_co"
    assert pool.executed == onboard_statements("acme-co")


async def test_provisioner_offboard_executes_drop():
    pool = _FakePool()
    schema = await TenantProvisioner(pool).offboard("acme-co")
    assert schema == "tenant_acme_co"
    assert pool.executed == offboard_statements("acme-co")


async def test_provisioner_wraps_failure_fail_closed():
    pool = _FakePool(fail=True)
    with pytest.raises(StoragePortError):
        await TenantProvisioner(pool).onboard("acme-co")


async def test_provisioner_rejects_unsafe_tenant():
    pool = _FakePool()
    with pytest.raises(TenantIsolationError):
        await TenantProvisioner(pool).onboard("evil; DROP")
