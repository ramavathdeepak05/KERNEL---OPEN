"""Conformance: spec §6 K·07 DoD requirements."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest

from quaicu.core.events import ActionCompletedEvent, InMemoryEventBus
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


def _action(tenant: str = "tenant-a", action_id: str = "act-conf-001") -> Action:
    tid = TenantId(tenant)
    return Action(
        id=ActionId(action_id),
        type="conformance.action",
        payload={},
        actor=Actor(id=ActorId("alice"), tenant=tid),
        tenant=tid,
        idempotency_key=IdempotencyKey(f"key-{action_id}"),
        state=ActionState.COMPLETED,
    )


def _entry(action: Action, seq: int = 0) -> LedgerEntry:
    return LedgerEntry(
        ledger_seq=seq,
        tenant=action.tenant,
        action_id=action.id,
        action_type=action.type,
        actor_id=action.actor.id,
        decision=Decision.ALLOW,
        policy_versions=("p@v1",),
        leaf_hash=hashlib.sha256(b"\x00conf").digest(),
        sealed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


@pytest.mark.conformance
async def test_events_only_after_seal() -> None:
    """Events must carry a ledger_seq — proof they are post-seal (seq 0 is valid for first entry)."""
    bus = InMemoryEventBus()
    action = _action()
    entry = _entry(action, seq=0)

    await bus.emit(action=action, entry=entry)

    assert len(bus.emitted) == 1
    event = bus.emitted[0]
    assert isinstance(event, ActionCompletedEvent)
    assert event.ledger_seq == 0


@pytest.mark.conformance
async def test_emit_failure_does_not_change_outcome() -> None:
    """A failing emit never propagates — the sealed outcome is preserved."""
    bus = InMemoryEventBus()

    async def always_fails(event: DomainEvent) -> None:
        raise RuntimeError("subscriber failure")

    bus.subscribe(ActionCompletedEvent, always_fails)
    action = _action(action_id="act-fail-conf")
    entry = _entry(action)

    await bus.emit(action=action, entry=entry)

    assert len(bus.emitted) == 1


@pytest.mark.conformance
async def test_events_carry_tenant_and_action_id() -> None:
    """Spec requires: events carry tenant + action_id."""
    bus = InMemoryEventBus()
    action = _action(tenant="acme-corp", action_id="act-tenant-check")
    entry = _entry(action)

    await bus.emit(action=action, entry=entry)

    event = bus.emitted[0]
    assert event.tenant == TenantId("acme-corp")
    assert event.action_id == ActionId("act-tenant-check")
