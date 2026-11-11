"""007 — RLS read-only hydration sentinel (replaces per-startup ALTER TABLE FORCE toggling).

Revision ID: 007
Revises: 004
Create Date: 2026-06-17

Startup hydration must read EVERY tenant's ledger rows to rebuild the in-memory tree. With FORCE RLS
on (migration 004), even the table owner is filtered to ``app.current_tenant`` — so the prior approach
toggled ``ALTER TABLE … NO FORCE / FORCE`` around each hydration read. That takes an ACCESS EXCLUSIVE
lock on every boot, requires the runtime role to own the table, and briefly disables FORCE for all
sessions.

Instead, redefine each tenant-isolation policy with a **read-only sentinel**: the ``USING`` (read)
clause also matches when ``app.current_tenant`` is the literal ``'*'``; the ``WITH CHECK`` (write)
clause stays strict (no sentinel), so a session set to ``'*'`` can read across tenants but can never
*write* another tenant's row. Hydration sets ``app.current_tenant = '*'`` for its read — no DDL, no
locks, works on managed Postgres (Cloud SQL) without a BYPASSRLS/superuser role.

``'*'`` is a safe sentinel: tenant ids are validated ``^[a-z0-9][a-z0-9_-]{0,50}$`` (see
``quaicu/adapters/storage/isolation``), so no real tenant can ever set ``app.current_tenant`` to ``'*'`` via
the per-request path — only the internal hydration code does.
"""

from __future__ import annotations

from alembic import op

revision = "007"
down_revision = "004"
branch_labels = None
depends_on = None

_TABLES = ("quaicu_actions", "quaicu_ledger_entries", "quaicu_ledger_sth")

_READ = (
    "tenant_id = current_setting('app.current_tenant', true) "
    "OR current_setting('app.current_tenant', true) = '*'"
)
_WRITE = "tenant_id = current_setting('app.current_tenant', true)"


def upgrade() -> None:
    for table in _TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}")
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation ON {table}
                USING ({_READ})
                WITH CHECK ({_WRITE})
            """
        )


def downgrade() -> None:
    # Revert to the strict migration-004 policy (no read sentinel).
    for table in _TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}")
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation ON {table}
                USING ({_WRITE})
                WITH CHECK ({_WRITE})
            """
        )
