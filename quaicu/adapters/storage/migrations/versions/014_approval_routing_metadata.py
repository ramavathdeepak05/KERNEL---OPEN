"""014 — durable HITL routing metadata on quaicu_approvals (D1-4).

Adds the notification routing metadata + signed resume link so a pending approval retains full context
across a restart: which channel/target notified the approver, and the signed approve (resume) link the
notification carried. All nullable + additive (older rows / the bare in-process port leave them NULL).

Revision ID: 014
Revises: 013
Create Date: 2026-07-02
"""

from __future__ import annotations

from alembic import op

revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None

_COLUMNS = ("notify_channel", "notify_target", "resume_link")


def upgrade() -> None:
    for col in _COLUMNS:
        op.execute(f"ALTER TABLE quaicu_approvals ADD COLUMN IF NOT EXISTS {col} TEXT")


def downgrade() -> None:
    for col in _COLUMNS:
        op.execute(f"ALTER TABLE quaicu_approvals DROP COLUMN IF EXISTS {col}")
