"""001 — create quaicu_actions table.

Revision ID: 001
Revises:
Create Date: 2026-06-10
"""

from __future__ import annotations

from alembic import op

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS quaicu_actions (
            id               TEXT        NOT NULL,
            tenant_id        TEXT        NOT NULL,
            idempotency_key  TEXT        NOT NULL,
            type             TEXT        NOT NULL,
            state            TEXT        NOT NULL,
            actor_id         TEXT        NOT NULL,
            actor_tenant     TEXT        NOT NULL,
            actor_roles      TEXT[]      NOT NULL DEFAULT '{}',
            actor_attributes JSONB       NOT NULL DEFAULT '{}',
            payload          JSONB       NOT NULL DEFAULT '{}',
            proposed_at      TIMESTAMPTZ NOT NULL,
            updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT quaicu_actions_pkey        PRIMARY KEY (id),
            CONSTRAINT quaicu_actions_idempotency UNIQUE (tenant_id, idempotency_key)
        )
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS quaicu_actions_tenant_state
            ON quaicu_actions (tenant_id, state)
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS quaicu_actions")
