"""016 — create witness_state table (durable, monotonic last-seen STH per tenant, D3-2 follow-up).

The ledger anchor witness (quaicu/adapters/ledger/witness.py) must remember the last Signed Tree Head it
cosigned for each tenant — otherwise a restart forgets, and a replayed smaller STH after restart is
treated as a fresh first STH and cosigned (a silent rewind slips through). `PostgresWitnessStateStore`
persists that memory here so the witness's monotonic guarantee survives restarts and is shared across
witness replicas. Control-plane table (no RLS).

Additive + idempotent (CREATE TABLE IF NOT EXISTS).
"""

from __future__ import annotations

from alembic import op

revision = "016"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS quaicu_witness_state (
            tenant_id   TEXT        NOT NULL,
            tree_size   BIGINT      NOT NULL,
            root_hash   BYTEA       NOT NULL,
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT quaicu_witness_state_pkey PRIMARY KEY (tenant_id)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS quaicu_witness_state")
