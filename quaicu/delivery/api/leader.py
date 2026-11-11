"""Single-runner gating for periodic background work on the shared plane (D4-1).

With ``--workers N`` (and multiple Cloud Run instances) every worker process runs `create_app`'s
lifespan, so a naive periodic task executes N× per cadence. For work that must run once per cadence
across the whole deployment (the D3-2 anchor pass), each worker races for a Postgres **session
advisory lock** before a pass; losers skip. The lock lives on its own short-lived connection and is
released (connection closed) after the pass, so a crashed leader never wedges the schedule.

No table, no migration, no changes to the frozen ledger/anchor surface — pure delivery-layer gating.
Deployments without Postgres (dsn=None) run the work unconditionally (single-process anyway).
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

log = logging.getLogger("quaicu.api.leader")

# Advisory-lock keyspace: hashtext() of these names. Stable strings, not magic numbers.
ANCHOR_LOCK_NAME = "quaicu:anchor"


@asynccontextmanager
async def try_advisory_gate(dsn: str | None, lock_name: str) -> AsyncIterator[bool]:
    """Yield True iff this process won the named advisory lock (run the pass), else False (skip).

    The session-level lock is held for the duration of the ``with`` block on a dedicated
    connection; closing the connection always releases it. A connection failure yields True
    (fail-open): duplicated periodic work is preferable to silently never running it.
    """
    if not dsn:
        yield True
        return
    conn = None
    try:
        import asyncpg

        conn = await asyncpg.connect(dsn)
        acquired = await conn.fetchval("SELECT pg_try_advisory_lock(hashtext($1))", lock_name)
    except Exception as exc:  # noqa: BLE001 — gating must never break the work itself
        log.warning("advisory gate %r unavailable (%s) — running ungated", lock_name, exc)
        if conn is not None:
            try:
                await conn.close()
            except Exception:  # noqa: BLE001
                pass
            conn = None
        yield True
        return
    try:
        yield bool(acquired)
    finally:
        try:
            if acquired:
                await conn.execute("SELECT pg_advisory_unlock(hashtext($1))", lock_name)
        finally:
            await conn.close()


def ledger_dsn_of(kernel: object) -> str | None:
    """Best-effort DSN of a kernel's durable ledger repository (None for in-memory ledgers).

    Reaches through the same attributes the anchor loop already uses (`kernel.engine._ledger`);
    returns None when any hop is absent so callers degrade to ungated execution.
    """
    ledger = getattr(getattr(kernel, "engine", None), "_ledger", None)
    repo = getattr(ledger, "_repository", None)
    dsn = getattr(repo, "_dsn", None)
    return dsn if isinstance(dsn, str) and dsn else None
