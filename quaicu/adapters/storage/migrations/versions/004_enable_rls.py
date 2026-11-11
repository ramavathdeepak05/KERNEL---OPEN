"""004 — enable row-level security on kernel tables (WS-E, F-07 defense in depth).

Adds an RLS policy to each shared kernel table keyed on ``current_setting('app.current_tenant')``.
A connection sets the tenant for its transaction via ``SELECT set_config('app.current_tenant', $1,
true)`` (see ``quaicu/adapters/storage/isolation.set_rls_tenant_sql``); thereafter the database itself only
returns / accepts that tenant's rows, even if a query forgot its ``tenant_id`` predicate. This is
additive to per-tenant schema isolation (``provisioner``) where that is used — belt and braces.

``app.current_tenant`` defaults to empty; ``current_setting(..., true)`` returns NULL when unset, so
the policies are written to deny-by-default (a connection that never set a tenant sees nothing).

Revision ID: 004
Revises: 003
Create Date: 2026-06-13
"""

from __future__ import annotations

from alembic import op

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None

_TABLES = ("quaicu_actions", "quaicu_ledger_entries", "quaicu_ledger_sth")


def upgrade() -> None:
    for table in _TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation ON {table}
                USING (tenant_id = current_setting('app.current_tenant', true))
                WITH CHECK (tenant_id = current_setting('app.current_tenant', true))
            """
        )


def downgrade() -> None:
    for table in _TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
