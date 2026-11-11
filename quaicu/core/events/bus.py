from __future__ import annotations

import logging
import threading
from collections.abc import Awaitable, Callable

from quaicu.core.events.model import DomainEvent, make_completed_event
from quaicu.core.types import Action, LedgerEntry

log = logging.getLogger("quaicu.events")

Subscriber = Callable[[DomainEvent], Awaitable[None]]


class InMemoryEventBus:
    """
    In-process event bus implementing the EventBus protocol.

    Subscribers are registered by event type and called on every emit.
    Fan-out is sequential (one subscriber failure does not block others).
    Idempotency: emitted action_ids are tracked; re-emitting the same action_id
    does not re-call subscribers (idempotent consumers).

    Thread-safety: subscription list is guarded by a lock; emit is async.
    """

    def __init__(self) -> None:
        self._subscribers: list[tuple[type[DomainEvent], Subscriber]] = []
        self._emitted_action_ids: set[str] = set()
        self._lock = threading.Lock()
        self._emitted_events: list[DomainEvent] = []

    def subscribe(self, event_type: type[DomainEvent], handler: Subscriber) -> None:
        """Register a subscriber for a specific event type (exact class match)."""
        with self._lock:
            self._subscribers.append((event_type, handler))

    async def emit(self, *, action: Action, entry: LedgerEntry) -> None:
        """Build and publish an ActionCompletedEvent. Idempotent by action_id."""
        action_key = str(action.id)
        with self._lock:
            if action_key in self._emitted_action_ids:
                log.debug("duplicate emit for action %s — skipped (idempotent)", action.id)
                return
            self._emitted_action_ids.add(action_key)

        event = make_completed_event(action, entry)

        with self._lock:
            self._emitted_events.append(event)
            matched = [(t, h) for t, h in self._subscribers if isinstance(event, t)]

        for _, handler in matched:
            try:
                await handler(event)
            except Exception as exc:  # noqa: BLE001 — subscriber failure must not propagate
                log.warning(
                    "subscriber error for event %s (action %s): %s",
                    event.event_id,
                    action.id,
                    exc,
                )

    @property
    def emitted(self) -> list[DomainEvent]:
        """All events emitted so far, in order."""
        with self._lock:
            return list(self._emitted_events)

    def clear(self) -> None:
        """Reset state (for test isolation)."""
        with self._lock:
            self._emitted_events.clear()
            self._emitted_action_ids.clear()
