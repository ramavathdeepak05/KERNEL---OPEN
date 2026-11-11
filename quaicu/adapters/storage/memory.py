"""In-memory StoragePort adapter.

Suitable for:
- Unit and integration tests (no database required).
- Sovereign single-process deployments (ephemeral; data lost on restart).

The async context manager yields ``_InMemoryTransaction`` which is a no-op:
the in-memory store commits immediately. The protocol marker is satisfied
structurally — no explicit base class needed.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any


class _InMemoryTransaction:
    """A no-op transaction for the in-memory adapter.

    Satisfies the ``Transaction`` Protocol structurally — no base class required.
    All writes are immediately visible (no isolation); suitable only for tests
    and single-process deployments.
    """

    def __init__(self, store: dict[str, Any]) -> None:
        self._store = store


class InMemoryStorageAdapter:
    """In-process StoragePort implementation.

    Exposes a shared dict as the backing store. Layers that need per-layer
    repositories layer their own key namespacing on top of the shared store.
    """

    def __init__(self) -> None:
        self._store: dict[str, Any] = {}

    @asynccontextmanager
    async def transaction(self):
        """Yield an _InMemoryTransaction. Commit is a no-op; rollback is a no-op."""
        yield _InMemoryTransaction(self._store)

    async def health_check(self) -> bool:
        return True
