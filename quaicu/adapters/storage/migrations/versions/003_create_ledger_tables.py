"""003 — create durable ledger tables (K·02 TrustLedger persistence).

Revision ID: 003
Revises: 002
Create Date: 2026-06-12
"""

from __future__ import annotations

from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
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
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS quaicu_ledger_entries_action
            ON quaicu_ledger_entries (tenant_id, action_id)
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS quaicu_ledger_sth (
            tenant_id   TEXT        NOT NULL,
            tree_size   BIGINT      NOT NULL,
            root_hash   BYTEA       NOT NULL,
            timestamp   TIMESTAMPTZ NOT NULL,
            signature   BYTEA       NOT NULL,
            key_id      TEXT        NOT NULL,
            CONSTRAINT quaicu_ledger_sth_pkey PRIMARY KEY (tenant_id)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS quaicu_ledger_sth")
    op.execute("DROP TABLE IF EXISTS quaicu_ledger_entries")
