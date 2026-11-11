"""Alembic migration environment — async asyncpg runner.

Usage::

    DATABASE_URL=postgresql://quaicu:pass@localhost/quaicu \\
        alembic -c quaicu/adapters/storage/migrations/alembic.ini upgrade head

No SQLAlchemy models are used; migrations are pure SQL via ``op.execute()``.
"""

from __future__ import annotations

import asyncio
import os

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

config = context.config

def _async_url(url: str) -> str:
    """Point a plain Postgres URL at the async driver this runner uses.

    The kernel's own DSNs are plain ``postgresql://…`` (that is what asyncpg takes), so the same
    value must work here. Without this, SQLAlchemy would load the synchronous psycopg2 driver for
    it and the async engine would refuse to start. A URL that already names a driver is left alone.
    """
    for scheme in ("postgresql://", "postgres://"):
        if url.startswith(scheme):
            return "postgresql+asyncpg://" + url[len(scheme) :]
    return url


# Read DSN from environment (never hardcode credentials).
DATABASE_URL = os.environ.get("DATABASE_URL", "")
if DATABASE_URL:
    config.set_main_option("sqlalchemy.url", _async_url(DATABASE_URL))


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting (for dry-run / diff)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=None,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):  # type: ignore[no-untyped-def]
    context.configure(connection=connection, target_metadata=None)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Connect and run migrations inside a real transaction."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
