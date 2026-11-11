from __future__ import annotations

import hashlib
from datetime import datetime, timezone


from quaicu.core.events import ActionCompletedEvent, ActionDeniedEvent, InMemoryEventBus
from quaicu.core.events.model import DomainEvent
from quaicu.core.types import (
    Action,
    ActionId,
    ActionState,
    Actor,
    ActorId,
    Decision,
    IdempotencyKey,
    LedgerEntry,
    TenantId,
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_action(tenant: str = "t1", action_type: str = "test.action") -> Action:
    tid = TenantId(tenant)
    return Action(
        id=ActionId(f"act-{tenant}"),
        type=action_type,
        payload={},
        actor=Actor(id=ActorId("alice"), tenant=tid),
        tenant=tid,
        idempotency_key=IdempotencyKey("key-1"),
        state=ActionState.COMPLETED,
    )


def _make_entry(action: Action, seq: int = 0) -> LedgerEntry:
    return LedgerEntry(
        ledger_seq=seq,
        tenant=action.tenant,
        action_id=action.id,
        action_type=action.type,
        actor_id=action.actor.id,
        decision=Decision.ALLOW,
        policy_versions=("p@v1",),
        leaf_hash=hashlib.sha256(b"\x00test").digest(),
        sealed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


async def test_emit_produces_completed_event() -> None:
    bus = InMemoryEventBus()
    action = _make_action()
    entry = _make_entry(action, seq=5)

    await bus.emit(action=action, entry=entry)

    assert len(bus.emitted) == 1
    event = bus.emitted[0]
    assert isinstance(event, ActionCompletedEvent)
    assert event.action_id == action.id
    assert event.tenant == action.tenant
    assert event.ledger_seq == 5


async def test_emitted_event_has_unique_event_id() -> None:
    bus = InMemoryEventBus()
    action1 = _make_action(tenant="t1")
    action2 = _make_action(tenant="t2")

    await bus.emit(action=action1, entry=_make_entry(action1))
    await bus.emit(action=action2, entry=_make_entry(action2))

    ids = [e.event_id for e in bus.emitted]
    assert ids[0] != ids[1]


async def test_subscriber_called_on_emit() -> None:
    bus = InMemoryEventBus()
    received: list[DomainEvent] = []

    async def handler(event: DomainEvent) -> None:
        received.append(event)

    bus.subscribe(ActionCompletedEvent, handler)
    action = _make_action()
    await bus.emit(action=action, entry=_make_entry(action))

    assert len(received) == 1
    assert isinstance(received[0], ActionCompletedEvent)


async def test_subscriber_only_called_for_matching_type() -> None:
    bus = InMemoryEventBus()
    received: list[DomainEvent] = []

    async def handler(event: DomainEvent) -> None:
        received.append(event)

    bus.subscribe(ActionDeniedEvent, handler)
    action = _make_action()
    await bus.emit(action=action, entry=_make_entry(action))

    assert received == []


async def test_subscriber_failure_does_not_propagate() -> None:
    bus = InMemoryEventBus()

    async def bad_handler(event: DomainEvent) -> None:
        raise RuntimeError("subscriber exploded")

    bus.subscribe(ActionCompletedEvent, bad_handler)
    action = _make_action()

    await bus.emit(action=action, entry=_make_entry(action))

    assert len(bus.emitted) == 1


async def test_idempotent_emit_skips_second() -> None:
    bus = InMemoryEventBus()
    call_count = 0

    async def handler(event: DomainEvent) -> None:
        nonlocal call_count
        call_count += 1

    bus.subscribe(ActionCompletedEvent, handler)
    action = _make_action()
    entry = _make_entry(action)

    await bus.emit(action=action, entry=entry)
    await bus.emit(action=action, entry=entry)

    assert call_count == 1
    assert len(bus.emitted) == 1


async def test_multiple_subscribers_all_called() -> None:
    bus = InMemoryEventBus()
    calls: list[int] = []

    async def handler1(event: DomainEvent) -> None:
        calls.append(1)

    async def handler2(event: DomainEvent) -> None:
        calls.append(2)

    bus.subscribe(ActionCompletedEvent, handler1)
    bus.subscribe(ActionCompletedEvent, handler2)
    action = _make_action()
    await bus.emit(action=action, entry=_make_entry(action))

    assert sorted(calls) == [1, 2]


async def test_emitted_list_in_order() -> None:
    bus = InMemoryEventBus()
    action1 = Action(
        id=ActionId("act-001"),
        type="t",
        payload={},
        actor=Actor(id=ActorId("alice"), tenant=TenantId("t1")),
        tenant=TenantId("t1"),
        idempotency_key=IdempotencyKey("k1"),
        state=ActionState.COMPLETED,
    )
    action2 = Action(
        id=ActionId("act-002"),
        type="t",
        payload={},
        actor=Actor(id=ActorId("alice"), tenant=TenantId("t2")),
        tenant=TenantId("t2"),
        idempotency_key=IdempotencyKey("k2"),
        state=ActionState.COMPLETED,
    )
    action3 = Action(
        id=ActionId("act-003"),
        type="t",
        payload={},
        actor=Actor(id=ActorId("alice"), tenant=TenantId("t3")),
        tenant=TenantId("t3"),
        idempotency_key=IdempotencyKey("k3"),
        state=ActionState.COMPLETED,
    )

    await bus.emit(action=action1, entry=_make_entry(action1, seq=0))
    await bus.emit(action=action2, entry=_make_entry(action2, seq=1))
    await bus.emit(action=action3, entry=_make_entry(action3, seq=2))

    ids = [e.action_id for e in bus.emitted]
    assert ids == [action1.id, action2.id, action3.id]


async def test_clear_resets_state() -> None:
    bus = InMemoryEventBus()
    call_count = 0

    async def handler(event: DomainEvent) -> None:
        nonlocal call_count
        call_count += 1

    bus.subscribe(ActionCompletedEvent, handler)
    action = _make_action()
    entry = _make_entry(action)

    await bus.emit(action=action, entry=entry)
    assert call_count == 1

    bus.clear()
    await bus.emit(action=action, entry=entry)
    assert call_count == 2
    assert len(bus.emitted) == 1


async def test_event_carries_leaf_hash() -> None:
    bus = InMemoryEventBus()
    action = _make_action()
    entry = _make_entry(action)

    await bus.emit(action=action, entry=entry)

    event = bus.emitted[0]
    assert isinstance(event, ActionCompletedEvent)
    assert event.leaf_hash == entry.leaf_hash


async def test_event_carries_decision() -> None:
    bus = InMemoryEventBus()
    action = _make_action()
    entry = LedgerEntry(
        ledger_seq=0,
        tenant=action.tenant,
        action_id=action.id,
        action_type=action.type,
        actor_id=action.actor.id,
        decision=Decision.REQUIRE_APPROVAL,
        policy_versions=("p@v1",),
        leaf_hash=hashlib.sha256(b"\x00test").digest(),
        sealed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    await bus.emit(action=action, entry=entry)

    event = bus.emitted[0]
    assert isinstance(event, ActionCompletedEvent)
    assert event.decision == Decision.REQUIRE_APPROVAL


async def test_emit_after_subscribe_calls_new_subscriber() -> None:
    bus = InMemoryEventBus()
    first_calls: list[DomainEvent] = []
    second_calls: list[DomainEvent] = []

    async def first_handler(event: DomainEvent) -> None:
        first_calls.append(event)

    bus.subscribe(ActionCompletedEvent, first_handler)

    action1 = Action(
        id=ActionId("act-first"),
        type="t",
        payload={},
        actor=Actor(id=ActorId("alice"), tenant=TenantId("t1")),
        tenant=TenantId("t1"),
        idempotency_key=IdempotencyKey("k-first"),
        state=ActionState.COMPLETED,
    )
    await bus.emit(action=action1, entry=_make_entry(action1))

    async def second_handler(event: DomainEvent) -> None:
        second_calls.append(event)

    bus.subscribe(ActionCompletedEvent, second_handler)

    action2 = Action(
        id=ActionId("act-second"),
        type="t",
        payload={},
        actor=Actor(id=ActorId("alice"), tenant=TenantId("t2")),
        tenant=TenantId("t2"),
        idempotency_key=IdempotencyKey("k-second"),
        state=ActionState.COMPLETED,
    )
    await bus.emit(action=action2, entry=_make_entry(action2))

    assert len(first_calls) == 2
    assert len(second_calls) == 1
    assert second_calls[0].action_id == action2.id
