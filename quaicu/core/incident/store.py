"""K·12 Incident — in-memory incident store.

Per-tenant; thread-safe via threading.Lock. All mutations return new frozen Incident values.
"""

from __future__ import annotations

import dataclasses
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from quaicu.core.errors import QUAICUError
from quaicu.core.incident.model import Incident, IncidentSeverity, IncidentStatus


class IncidentNotFoundError(QUAICUError):
    pass


class IncidentStore:
    """In-memory per-tenant incident registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: dict[str, dict[str, Incident]] = {}  # tenant_id → {incident_id → Incident}

    def open_incident(
        self,
        *,
        tenant_id: str,
        trigger_type: str,
        severity: IncidentSeverity,
        description: str,
        triggering_ledger_seq: int | None = None,
        triggering_action_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Incident:
        incident = Incident(
            incident_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            trigger_type=trigger_type,
            severity=severity,
            status=IncidentStatus.OPEN,
            description=description,
            opened_at=datetime.now(tz=timezone.utc),
            triggering_ledger_seq=triggering_ledger_seq,
            triggering_action_id=triggering_action_id,
            metadata=metadata or {},
        )
        with self._lock:
            self._store.setdefault(tenant_id, {})[incident.incident_id] = incident
        return incident

    def get(self, tenant_id: str, incident_id: str) -> Incident | None:
        with self._lock:
            return self._store.get(tenant_id, {}).get(incident_id)

    def require(self, tenant_id: str, incident_id: str) -> Incident:
        inc = self.get(tenant_id, incident_id)
        if inc is None:
            raise IncidentNotFoundError(
                f"Incident {incident_id!r} not found for tenant {tenant_id!r}",
                detail={"incident_id": incident_id, "tenant_id": tenant_id},
            )
        return inc

    def list_for_tenant(self, tenant_id: str) -> list[Incident]:
        with self._lock:
            return list(self._store.get(tenant_id, {}).values())

    def update_status(
        self, tenant_id: str, incident_id: str, status: IncidentStatus
    ) -> Incident:
        with self._lock:
            inc = self._store.get(tenant_id, {}).get(incident_id)
            if inc is None:
                raise IncidentNotFoundError(
                    f"Incident {incident_id!r} not found",
                    detail={"incident_id": incident_id},
                )
            resolved_at = datetime.now(tz=timezone.utc) if status == IncidentStatus.RESOLVED else inc.resolved_at
            updated = dataclasses.replace(inc, status=status, resolved_at=resolved_at)
            self._store[tenant_id][incident_id] = updated
        return updated

    def link_rollback_action(
        self, tenant_id: str, incident_id: str, action_id: str
    ) -> Incident:
        """Record a governed rollback action ID against this incident."""
        with self._lock:
            inc = self._store.get(tenant_id, {}).get(incident_id)
            if inc is None:
                raise IncidentNotFoundError(
                    f"Incident {incident_id!r} not found",
                    detail={"incident_id": incident_id},
                )
            updated = dataclasses.replace(
                inc, rollback_action_ids=(*inc.rollback_action_ids, action_id)
            )
            self._store[tenant_id][incident_id] = updated
        return updated
