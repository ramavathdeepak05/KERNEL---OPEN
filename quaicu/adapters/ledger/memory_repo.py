"""InMemoryLedgerRepository — dict-backed durable-ledger backend for dev/tests.

Implements the `LedgerRepository` Protocol structurally. It is "durable" only for the lifetime of
the process, but it exercises the full write-through + hydrate path (the `TrustLedger` persists
through it on seal and rebuilds from it on hydrate), so the durability contract can be unit-tested
without a database. Production uses `PostgresLedgerRepository`.

Mirrors the Postgres adapter's multi-worker linearization contract (D4-1): a differing entry at an
existing (tenant, ledger_seq) raises `LedgerSequenceConflictError` (an identical replay is a no-op
success), and the STH save is advance-only. Sharing one instance between two `TrustLedger`s
simulates two workers over one database in unit tests.
"""

from __future__ import annotations

import threading

from quaicu.core.errors import LedgerSequenceConflictError
from quaicu.core.ledger.signer import SignedTreeHead
from quaicu.core.types import LedgerEntry, TenantId


class InMemoryLedgerRepository:
    """Thread-safe in-memory `LedgerRepository`. Entries keyed by (tenant, ledger_seq)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, int], LedgerEntry] = {}
        self._sths: dict[str, SignedTreeHead] = {}

    async def append_entry(self, entry: LedgerEntry) -> None:
        key = (str(entry.tenant), entry.ledger_seq)
        with self._lock:
            existing = self._entries.get(key)
            if existing is None:
                self._entries[key] = entry
                return
            if bytes(existing.leaf_hash) == bytes(entry.leaf_hash):
                return  # idempotent replay of the same sealed entry
            raise LedgerSequenceConflictError(
                f"seq {entry.ledger_seq} for tenant {entry.tenant} already taken by a "
                "different entry (concurrent seal from another worker)",
                detail={"tenant": str(entry.tenant), "ledger_seq": entry.ledger_seq},
            )

    async def load_entries(self) -> list[LedgerEntry]:
        with self._lock:
            entries = list(self._entries.values())
        return sorted(entries, key=lambda e: (str(e.tenant), e.ledger_seq))

    async def load_tenant_entries(self, tenant: TenantId) -> list[LedgerEntry]:
        with self._lock:
            entries = [e for (t, _), e in self._entries.items() if t == str(tenant)]
        return sorted(entries, key=lambda e: e.ledger_seq)

    async def save_sth(self, tenant: TenantId, sth: SignedTreeHead) -> None:
        with self._lock:
            stored = self._sths.get(str(tenant))
            if stored is not None and stored.tree_size > sth.tree_size:
                return  # advance-only: a stale worker's late save never regresses the head
            self._sths[str(tenant)] = sth

    async def load_sths(self) -> dict[str, SignedTreeHead]:
        with self._lock:
            return dict(self._sths)

    async def close(self) -> None:
        return None
