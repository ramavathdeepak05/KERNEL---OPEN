"""K·12 Incident — domain models.

Rollback is a governed action through the full lifecycle — no out-of-band effects.
An Incident links to the triggering ledger entry so pre-incident state can be
reconstructed by replaying K·02 (F-09).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVING = "RESOLVING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


@dataclass(frozen=True)
class Incident:
    """An operational incident linked to one or more sealed ledger entries.

    ``triggering_ledger_seq`` and ``triggering_action_id`` are the K·02 reference needed
    to replay the ledger back to pre-incident state (F-09).

    ``rollback_action_ids`` records which governed actions were run as rollbacks — each
    went through the full lifecycle (K·01 → K·03 → K·05 → K·02 → K·07), never out-of-band.
    """

    incident_id: str
    tenant_id: str
    trigger_type: str  # "drift_breach" | "manual" | "threshold_exceeded" | ...
    severity: IncidentSeverity
    status: IncidentStatus
    description: str
    opened_at: datetime
    triggering_ledger_seq: int | None = None
    triggering_action_id: str | None = None
    resolved_at: datetime | None = None
    rollback_action_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
