"""StoragePort — FROZEN. Transactional storage for kernel-owned tables ONLY."""

from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from typing import Protocol, runtime_checkable

from quaicu.core.types import Transaction


@runtime_checkable
class StoragePort(Protocol):
    """Transactional storage for the kernel's own schema. Core NEVER reads or writes host domain
    tables, and never assumes the host's database. Implementation: postgres (schema-per-tenant + RLS).

    Fail-closed contract:
      - Commit failure → raise `StoragePortError`. Never swallow.
      - Concurrent write conflict (unique constraint) → raise `StoragePortError` with `detail`
        identifying the conflict, so callers can distinguish an idempotency duplicate from a real error.
      - `health_check` raises `StoragePortError` when unreachable; it never returns False silently.
    """

    def transaction(self) -> AbstractAsyncContextManager[Transaction]:
        """Return an async context manager yielding a `Transaction`. On clean exit it commits; on an
        exception it rolls back. Tenant scoping (search_path + RLS) is applied per transaction by the
        adapter."""
        ...

    async def health_check(self) -> bool:
        """Return True if the backend is reachable. Raise `StoragePortError` if not."""
        ...
