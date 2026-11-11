"""013 — create approvals table (durable HITL queue shared by every worker).

The in-memory ApprovalStore is per-process, so a horizontally-scaled (multi-instance) deployment shows
an inconsistent `/v1/approvals` queue. `PostgresApprovalStore` (quaicu/adapters/hitl/postgres_store.py) persists
HITL approval records here so the queue is consistent across instances. Control-plane table (no RLS,
by design) — `list_pending`/`pending_count` are cross-tenant (operator queue + dashboard
depth) and tenant isolation is enforced at the route (quaicu/delivery/api/routes/approvals.py).

Additive + idempotent (CREATE TABLE IF NOT EXISTS).
"""

from __future__ import annotations

from alembic import op

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS quaicu_approvals (
            handle_id          TEXT        NOT NULL,
            action_id          TEXT        NOT NULL,
            tenant_id          TEXT        NOT NULL,
            required_approvers TEXT        NOT NULL DEFAULT '[]',
            requested_at       TIMESTAMPTZ NOT NULL,
            decision           TEXT        NOT NULL DEFAULT 'PENDING',
            decided_by         TEXT,
            decided_at         TIMESTAMPTZ,
            expires_at         TIMESTAMPTZ,
            proposed_by        TEXT,
            CONSTRAINT quaicu_approvals_pkey PRIMARY KEY (handle_id)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS quaicu_approvals_pending ON quaicu_approvals (decision)")
    op.execute("CREATE INDEX IF NOT EXISTS quaicu_approvals_action ON quaicu_approvals (action_id)")
    op.execute("CREATE INDEX IF NOT EXISTS quaicu_approvals_tenant ON quaicu_approvals (tenant_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS quaicu_approvals")
