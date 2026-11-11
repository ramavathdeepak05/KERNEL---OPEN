"""012 — create shred-keys table (durable KMS-wrapped DEKs for provable erasure, W6-4).

Revision ID: 012
Revises: 007
Create Date: 2026-06-24

Durable home for the per-subject data-encryption keys behind crypto-shredding (`quaicu/adapters/erasure`).
Only KMS-**wrapped** DEKs are stored (the plaintext DEK never persists); ``destroy`` nulls the wrapped
blob and sets the tombstone, so an erased subject can never be resurrected. Like the other control-plane
registries (accounts/api_keys/members), this is intentionally NOT under RLS — the keyring loads by
(tenant, subject) across tenants.
"""

from __future__ import annotations

from alembic import op

revision = "012"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS quaicu_shred_keys (
            tenant_id   TEXT        NOT NULL,
            subject_id  TEXT        NOT NULL,
            key_id      TEXT        NOT NULL DEFAULT '',
            wrapped_dek BYTEA,
            tombstoned  BOOLEAN     NOT NULL DEFAULT FALSE,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT quaicu_shred_keys_pkey PRIMARY KEY (tenant_id, subject_id)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS quaicu_shred_keys_key_id ON quaicu_shred_keys (key_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS quaicu_shred_keys")
