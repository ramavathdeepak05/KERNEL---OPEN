"""K·02 TrustLedger — durable persistence port.

`LedgerRepository` is the structural async Protocol a durable ledger backend implements (in-memory
for dev/single-process, Postgres for production). The `TrustLedger` uses it as a write-through
collaborator: the in-memory per-tenant Merkle trees stay the fast read/proof path, and the
repository persists each sealed `LedgerEntry` plus the latest Signed Tree Head so the log survives a
restart and can be re-hydrated (the tree is rebuilt from the stored leaf hashes).

This is a port (core depends only on this Protocol) — concrete adapters live under `adapters/ledger/`.
Implementations MUST wrap backend faults in `core.errors.LedgerPersistenceError`; the hot read path
(proofs, get_entries) never calls this — only `seal` (write-through) and `hydrate` (startup) do.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from quaicu.core.ledger.signer import SignedTreeHead
from quaicu.core.types import LedgerEntry, TenantId


@runtime_checkable
class LedgerRepository(Protocol):
    """Durable store for sealed ledger entries and per-tenant Signed Tree Heads."""

    async def append_entry(self, entry: LedgerEntry) -> None:
        """Persist one sealed entry. The insert is the multi-worker linearization point.

        Contract (D4-1): if a row already exists at (tenant, ledger_seq) with the SAME leaf hash,
        this is an idempotent replay — succeed as a no-op. If it exists with a DIFFERENT leaf hash,
        another worker won the sequence slot — raise `LedgerSequenceConflictError` so the caller
        can rehydrate its stale tree and retry. Never silently drop a differing entry."""
        ...

    async def load_entries(self) -> list[LedgerEntry]:
        """Return every persisted entry across all tenants, ordered by (tenant, ledger_seq).

        The `TrustLedger` groups these by tenant and rebuilds each tenant's Merkle tree from the
        stored leaf hashes on hydrate."""
        ...

    async def load_tenant_entries(self, tenant: TenantId) -> list[LedgerEntry]:
        """Return one tenant's entries ordered by ledger_seq (tenant-scoped read).

        Used by `TrustLedger` to rehydrate a single tenant's tree after a sequence conflict
        without reloading every tenant."""
        ...

    async def save_sth(self, tenant: TenantId, sth: SignedTreeHead) -> None:
        """Upsert the latest Signed Tree Head for `tenant` (one row per tenant).

        Contract (D4-1): advance-only — an incoming STH with a smaller tree_size than the stored
        one must be skipped (a stale worker's late save can never regress the durable head)."""
        ...

    async def load_sths(self) -> dict[str, SignedTreeHead]:
        """Return the latest STH per tenant, keyed by tenant id string."""
        ...

    async def close(self) -> None:
        """Release any backend resources (connection pools). No-op for in-memory."""
        ...
