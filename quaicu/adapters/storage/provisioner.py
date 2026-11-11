"""TenantProvisioner — create/drop a tenant's isolated schema (schema-per-tenant deployments; WS-E, F-07).

`onboard_statements(tenant)` returns the ordered SQL to stand up a tenant's own schema with its own
copy of every kernel table (actions + ledger). The statements run inside one transaction with
``search_path`` pinned to the new schema, so the ``CREATE TABLE``s land *in that schema*, not
``public`` — physical schema-per-tenant. `offboard_statements(tenant)` drops it (CASCADE) for tenant
deletion / GDPR.

The SQL generation is pure and unit-tested; `onboard`/`offboard` execute it on an asyncpg pool. Table
DDL mirrors migrations 001/003 (kept schema-qualified-free so it applies under the pinned
``search_path``).
"""

from __future__ import annotations

from typing import Any

from quaicu.adapters.storage.isolation import (
    create_tenant_schema_sql,
    drop_tenant_schema_sql,
    safe_schema_name,
    search_path_sql,
)
from quaicu.core.errors import StoragePortError
from quaicu.core.types import TenantId

# Per-tenant table DDL — identical shape to the shared tables, created under the pinned search_path.
_ACTIONS_DDL = """
CREATE TABLE IF NOT EXISTS quaicu_actions (
    id                TEXT        NOT NULL,
    tenant_id         TEXT        NOT NULL,
    idempotency_key   TEXT        NOT NULL,
    type              TEXT        NOT NULL,
    state             TEXT        NOT NULL,
    actor_id          TEXT        NOT NULL,
    actor_tenant      TEXT        NOT NULL,
    actor_roles       JSONB       NOT NULL DEFAULT '[]',
    actor_attributes  JSONB       NOT NULL DEFAULT '{}',
    payload           JSONB       NOT NULL DEFAULT '{}',
    proposed_at       TIMESTAMPTZ,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT quaicu_actions_pkey PRIMARY KEY (tenant_id, idempotency_key)
)
""".strip()

_LEDGER_ENTRIES_DDL = """
CREATE TABLE IF NOT EXISTS quaicu_ledger_entries (
    tenant_id         TEXT        NOT NULL,
    ledger_seq        BIGINT      NOT NULL,
    action_id         TEXT        NOT NULL,
    action_type       TEXT        NOT NULL,
    actor_id          TEXT        NOT NULL,
    decision          TEXT        NOT NULL,
    policy_versions   JSONB       NOT NULL DEFAULT '[]',
    leaf_hash         BYTEA       NOT NULL,
    sealed_at         TIMESTAMPTZ NOT NULL,
    approver          TEXT,
    consent_state     JSONB       NOT NULL DEFAULT '{}',
    recorded_result   JSONB       NOT NULL DEFAULT '{}',
    recorded_outputs  JSONB       NOT NULL DEFAULT '{}',
    actor_roles       JSONB       NOT NULL DEFAULT '[]',
    CONSTRAINT quaicu_ledger_entries_pkey PRIMARY KEY (tenant_id, ledger_seq)
)
""".strip()

_LEDGER_STH_DDL = """
CREATE TABLE IF NOT EXISTS quaicu_ledger_sth (
    tenant_id   TEXT        NOT NULL,
    tree_size   BIGINT      NOT NULL,
    root_hash   BYTEA       NOT NULL,
    timestamp   TIMESTAMPTZ NOT NULL,
    signature   BYTEA       NOT NULL,
    key_id      TEXT        NOT NULL,
    CONSTRAINT quaicu_ledger_sth_pkey PRIMARY KEY (tenant_id)
)
""".strip()

_PER_TENANT_TABLE_DDL = (_ACTIONS_DDL, _LEDGER_ENTRIES_DDL, _LEDGER_STH_DDL)


def onboard_statements(tenant: TenantId | str, *, prefix: str = "tenant_") -> list[str]:
    """The ordered SQL to create a tenant's isolated schema + its tables.

    Run these inside a single transaction: CREATE SCHEMA, pin ``search_path`` to it, then create each
    table (which therefore lands in the tenant's schema, not ``public``).
    """
    return [
        create_tenant_schema_sql(tenant, prefix=prefix),
        search_path_sql(tenant, prefix=prefix),
        *_PER_TENANT_TABLE_DDL,
    ]


def offboard_statements(tenant: TenantId | str, *, prefix: str = "tenant_") -> list[str]:
    """The SQL to drop a tenant's schema and all its data (CASCADE)."""
    return [drop_tenant_schema_sql(tenant, prefix=prefix)]


class TenantProvisioner:
    """Creates/drops per-tenant schemas on an asyncpg pool (schema-per-tenant onboarding)."""

    def __init__(self, pool: Any, *, prefix: str = "tenant_") -> None:
        self._pool = pool
        self._prefix = prefix

    def schema_name(self, tenant: TenantId | str) -> str:
        return safe_schema_name(tenant, prefix=self._prefix)

    async def onboard(self, tenant: TenantId | str) -> str:
        """Create the tenant's schema + tables in one transaction. Returns the schema name."""
        return await self._run(onboard_statements(tenant, prefix=self._prefix), tenant, "onboard")

    async def offboard(self, tenant: TenantId | str) -> str:
        """Drop the tenant's schema (CASCADE). Returns the schema name."""
        return await self._run(offboard_statements(tenant, prefix=self._prefix), tenant, "offboard")

    async def _run(self, statements: list[str], tenant: TenantId | str, op: str) -> str:
        try:
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    for sql in statements:
                        await conn.execute(sql)
        except Exception as exc:  # noqa: BLE001 — fail-closed, wrap as a storage error
            raise StoragePortError(
                f"Tenant {op} failed for {tenant!r}: {exc}", detail={"tenant": str(tenant)}
            ) from exc
        return self.schema_name(tenant)
