"""InMemoryEventBusAdapter — in-process event bus for dev and single-process use.

Registers as adapter key ``"memory_events"`` in the Kernel adapter registry.
Emitted entries are appended to an in-memory list. A pluggable subscriber
list allows components to react to events within the same process (e.g.
incident detection, drift monitoring).

Not suitable for distributed deployments — use a Kafka or Redis Streams
adapter for cross-service fan-out.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

from quaicu.core.types import Action, LedgerEntry

log = logging.getLogger("quaicu.events")


class InMemoryEventBusAdapter:
    """Thread-safe in-memory event bus. Stores all emitted entries."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._emitted: list[LedgerEntry] = []
        self._subscribers: list[Callable[[Action, LedgerEntry], Any]] = []

    async def emit(self, *, action: Action, entry: LedgerEntry) -> None:
        with self._lock:
            self._emitted.append(entry)
            subs = list(self._subscribers)

        for sub in subs:
            try:
                result = sub(action, entry)
                if hasattr(result, "__await__"):
                    await result  # type: ignore[misc]
            except Exception:
                # Subscribers are best-effort; never fail the emit path. But a swallowed exception
                # would silently break side-effects (drift/fairness sweeps, webhooks), so log it.
                log.exception("event subscriber failed during emit (action=%s)", action.id)

    def subscribe(self, fn: Callable[[Action, LedgerEntry], Any]) -> None:
        with self._lock:
            self._subscribers.append(fn)

    @property
    def emitted(self) -> list[LedgerEntry]:
        with self._lock:
            return list(self._emitted)
