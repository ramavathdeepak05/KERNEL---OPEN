from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from quaicu.core.types import Action, ActionId, Decision, LedgerEntry, TenantId


@dataclass(frozen=True)
class DomainEvent:
    event_id: str
    action_id: ActionId
    tenant: TenantId
    emitted_at: datetime


@dataclass(frozen=True)
class ActionCompletedEvent(DomainEvent):
    """Emitted after a governed action successfully seals and completes."""

    action_type: str
    decision: Decision
    ledger_seq: int
    leaf_hash: bytes


@dataclass(frozen=True)
class ActionDeniedEvent(DomainEvent):
    """Future: emitted when an action is denied. Defined here for completeness."""

    action_type: str
    reason: str = ""


@dataclass(frozen=True)
class ActionHaltedEvent(DomainEvent):
    """Future: emitted when an action is halted. Defined here for completeness."""

    action_type: str
    reason: str = ""


def make_completed_event(action: Action, entry: LedgerEntry) -> ActionCompletedEvent:
    return ActionCompletedEvent(
        event_id=str(uuid.uuid4()),
        action_id=action.id,
        tenant=action.tenant,
        emitted_at=datetime.now(tz=timezone.utc),
        action_type=action.type,
        decision=entry.decision,
        ledger_seq=entry.ledger_seq,
        leaf_hash=entry.leaf_hash,
    )
