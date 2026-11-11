"""K·12 Incident conformance tests — spec-derived golden cases.

Invariants tested:
  - Incident links to triggering ledger entry (F-09 replay reference).
  - Rollback action IDs are governed actions, not out-of-band effects.
  - Per-tenant isolation: incidents scoped to their tenant.
  - Status transitions are valid and reflected in returned incident.
  - Resolved incidents have resolved_at set.
"""

from __future__ import annotations

import pytest

from quaicu.core.incident.model import IncidentSeverity, IncidentStatus
from quaicu.core.incident.store import IncidentStore

TENANT = "ciro-bank"


@pytest.mark.conformance
def test_incident_links_to_ledger_entry_for_replay():
    """Incident must record triggering_ledger_seq for K·02 replay (F-09)."""
    store = IncidentStore()
    inc = store.open_incident(
        tenant_id=TENANT,
        trigger_type="drift_breach",
        severity=IncidentSeverity.HIGH,
        description="Drift PSI exceeded 0.25",
        triggering_ledger_seq=100,
        triggering_action_id="act-100",
    )
    assert inc.triggering_ledger_seq == 100
    assert inc.triggering_action_id == "act-100"


@pytest.mark.conformance
def test_rollback_is_governed_action_linked_not_out_of_band():
    """Rollback must run as a governed action — link its ID, never auto-execute."""
    store = IncidentStore()
    inc = store.open_incident(
        tenant_id=TENANT,
        trigger_type="manual",
        severity=IncidentSeverity.CRITICAL,
        description="Manual incident",
    )
    # Caller triggers a governed rollback action through K·01→K·07 and links its ID
    updated = store.link_rollback_action(TENANT, inc.incident_id, "governed-rollback-act-99")
    assert "governed-rollback-act-99" in updated.rollback_action_ids


@pytest.mark.conformance
def test_incident_tenant_isolation():
    """Incidents opened for tenant A must not appear for tenant B."""
    store = IncidentStore()
    store.open_incident(
        tenant_id=TENANT, trigger_type="drift_breach",
        severity=IncidentSeverity.LOW, description="Bank A only",
    )
    assert len(store.list_for_tenant("other-bank")) == 0


@pytest.mark.conformance
def test_resolved_incident_has_resolved_at():
    """Resolution must be timestamped — required for audit trail."""
    store = IncidentStore()
    inc = store.open_incident(
        tenant_id=TENANT, trigger_type="drift_breach",
        severity=IncidentSeverity.MEDIUM, description="Drift",
    )
    resolved = store.update_status(TENANT, inc.incident_id, IncidentStatus.RESOLVED)
    assert resolved.resolved_at is not None
    assert resolved.status == IncidentStatus.RESOLVED


@pytest.mark.conformance
def test_open_incident_status_is_open():
    """Freshly opened incidents must start in OPEN status."""
    store = IncidentStore()
    inc = store.open_incident(
        tenant_id=TENANT, trigger_type="drift_breach",
        severity=IncidentSeverity.HIGH, description="Auto-detected breach",
    )
    assert inc.status == IncidentStatus.OPEN
