"""002 — create policy + impact-report tables (durable K·01 policy store).

Revision ID: 002
Revises: 001
Create Date: 2026-06-10
"""

from __future__ import annotations

from alembic import op

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS quaicu_policies (
            id               TEXT        NOT NULL,
            version          INTEGER     NOT NULL,
            governs          TEXT        NOT NULL,
            scope            JSONB       NOT NULL DEFAULT '{}',
            condition        TEXT        NOT NULL,
            decision         TEXT        NOT NULL,
            approvers        TEXT[]      NOT NULL DEFAULT '{}',
            regulatory_refs  TEXT[]      NOT NULL DEFAULT '{}',
            lifecycle        TEXT        NOT NULL,
            updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT quaicu_policies_pkey PRIMARY KEY (id, version)
        )
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS quaicu_policies_governs_lifecycle
            ON quaicu_policies (governs, lifecycle)
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS quaicu_policy_impact_reports (
            policy_id              TEXT             NOT NULL,
            version                INTEGER          NOT NULL,
            reviewed_by            TEXT             NOT NULL,
            reviewed_at            TIMESTAMPTZ      NOT NULL,
            decision_distribution  JSONB            NOT NULL DEFAULT '{}',
            flip_count             INTEGER          NOT NULL DEFAULT 0,
            fairness_delta         DOUBLE PRECISION NOT NULL DEFAULT 0,
            acknowledged           BOOLEAN          NOT NULL DEFAULT false,
            CONSTRAINT quaicu_policy_impact_reports_pkey PRIMARY KEY (policy_id, version)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS quaicu_policy_impact_reports")
    op.execute("DROP TABLE IF EXISTS quaicu_policies")
